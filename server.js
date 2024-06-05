const express = require('express');
const axios = require('axios');
const cors = require('cors');
const mysql = require('mysql');
const app = express();
const PORT = process.env.PORT || 5000;
app.use(express.json());
app.use(cors());

//VirusTotal API Endpoint
app.get('/url-report', async (req, res) => {
  try {
    const { apikey, resource, allinfo, scan } = req.query;
    const response = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${apikey}&resource=${resource}&allinfo=${allinfo}&scan=${scan}`, {
      headers: {
        'Accept': 'application/json'
      }
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//connect to db
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'extenalertdatabase'
});

const connectToDatabase = () => {
  db.connect((err) => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      return;
    }
    console.log('MySQL Connected...');

    // Create tables if they don't exist
    const createWhitelistedReportsTable = `
      CREATE TABLE IF NOT EXISTS whitelisted_urls (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30),
        threat_level VARCHAR(30)
      );
    `;
    db.query(createWhitelistedReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating whitelisted_urls table:', err);
        return;
      }
      console.log('whitelisted_urls table created or already exists:', result);
    });

    const createBlacklistedUrlsTable = `
      CREATE TABLE IF NOT EXISTS blacklisted_urls (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30),
        threat_level VARCHAR(30)
      );
    `;
    db.query(createBlacklistedUrlsTable, (err, result) => {
      if (err) {
        console.error('Error creating blacklisted_urls table:', err);
        return;
      }
      console.log('blacklisted_urls table created or already exists:', result);
    });

    const createIncomingReportsTable = `
      CREATE TABLE IF NOT EXISTS incoming_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30),
        threat_level VARCHAR(30)
      );
    `;
    db.query(createIncomingReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating incoming_reports table:', err);
        return;
      }
      console.log('incoming_reports table created or already exists:', result);
    });

    const createIncomingVirusTotalReportsTable = `
      CREATE TABLE IF NOT EXISTS virustotal_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30),
        threat_level VARCHAR(30)
      );
    `;
    db.query(createIncomingVirusTotalReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating virustotal_reports table:', err);
        return;
      }
      console.log('virustotal_reports table created or already exists:', result);
    });

    const createUnratedReportsTable = `
    CREATE TABLE IF NOT EXISTS unrated_reports (
      id INT AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255),
      status VARCHAR(30)
    );
    `;
    db.query(createUnratedReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating unrated_reports table:', err);
        return;
      }
      console.log('unrated_reports table created or already exists:', result);
    });

    const createUsersTable = `
    CREATE TABLE users (
      id INT PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL
    );
    `;
    db.query(createUsersTable, (err, result) => {
      if (err) {
        console.error('Error creating users table:', err);
        return;
      }
      console.log('users table created or already exists:', result);
    });

    // Drop existing procedure if it exists
    db.query('DROP PROCEDURE IF EXISTS process_incoming_reports', (err, result) => {
      if (err) {
        console.error('Error dropping existing procedure:', err);
        return;
      }

      // Create stored procedure
      const createProcedure = `
      CREATE PROCEDURE process_incoming_reports()
      BEGIN
        DECLARE done INT DEFAULT FALSE;
        DECLARE report_url VARCHAR(255);
        DECLARE report_status VARCHAR(30);
        DECLARE report_count INT;
        DECLARE cur CURSOR FOR 
            SELECT url, status, COUNT(*) as cnt
            FROM incoming_reports
            GROUP BY url, status
            HAVING cnt >= 10;

        DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

        OPEN cur;

        read_loop: LOOP
            FETCH cur INTO report_url, report_status, report_count;
            IF done THEN
                LEAVE read_loop;
            END IF;

            IF report_status = 'benign' THEN
                IF NOT EXISTS (SELECT 1 FROM whitelisted_urls WHERE url = report_url) THEN
                    INSERT INTO whitelisted_urls (url, status, threat_level) VALUES (report_url, 'benign', 'Low');
                ELSE
                    UPDATE whitelisted_urls SET threat_level = 'Low' WHERE url = report_url;
                END IF;
                DELETE FROM incoming_reports WHERE url = report_url AND status = report_status;
            ELSE -- phishing status
                IF report_count >= 25 THEN
                    IF EXISTS (SELECT 1 FROM blacklisted_urls WHERE url = report_url) THEN
                        UPDATE blacklisted_urls SET threat_level = 'High' WHERE url = report_url;
                    ELSE
                        INSERT INTO blacklisted_urls (url, status, threat_level) VALUES (report_url, 'phishing', 'High');
                    END IF;
                    DELETE FROM incoming_reports WHERE url = report_url AND status = report_status;
                ELSE -- count is between 10 and 24
                    IF EXISTS (SELECT 1 FROM blacklisted_urls WHERE url = report_url) THEN
                        UPDATE blacklisted_urls SET threat_level = 'Moderate' WHERE url = report_url;
                    ELSE
                        INSERT INTO blacklisted_urls (url, status, threat_level) VALUES (report_url, 'phishing', 'Moderate');
                    END IF;
                END IF;
            END IF;
        END LOOP;

        CLOSE cur;
      END ;
      `;
      db.query(createProcedure, (err, result) => {
        if (err) {
          console.error('Error creating procedure:', err);
          return;
        }
        console.log('Procedure created successfully');
      });
      // Drop existing procedure if it exists
      db.query('DROP PROCEDURE IF EXISTS process_virustotal_reports', (err, result) => {
        if (err) {
            console.error('Error dropping existing procedure:', err);
            return;
        }

        // Create stored procedure
        const createProcedure = `
            CREATE PROCEDURE process_virustotal_reports()
            BEGIN
            DECLARE done INT DEFAULT FALSE;
            DECLARE report_url VARCHAR(255);
            DECLARE report_status VARCHAR(30);
            DECLARE report_threat_level VARCHAR(30);
            DECLARE report_count INT;
            DECLARE cur CURSOR FOR 
                SELECT url, status, threat_level, COUNT(*) as cnt
                FROM virustotal_reports
                GROUP BY url, status, threat_level
                HAVING cnt >= 10;
        
            DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
        
            OPEN cur;
        
            read_loop: LOOP
                FETCH cur INTO report_url, report_status, report_threat_level, report_count;
                IF done THEN
                    LEAVE read_loop;
                END IF;
        
                IF report_count >= 10 THEN
                    IF report_status = 'benign' THEN
                        IF NOT EXISTS (SELECT 1 FROM whitelisted_urls WHERE url = report_url) THEN
                            INSERT INTO whitelisted_urls (url, status, threat_level) VALUES (report_url, 'benign', 'Low');
                        ELSE
                            UPDATE whitelisted_urls SET threat_level = 'Low' WHERE url = report_url;
                        END IF;
                        DELETE FROM virustotal_reports WHERE url = report_url AND status = report_status;
                    ELSE -- phishing or other malicious status
                        IF NOT EXISTS (SELECT 1 FROM blacklisted_urls WHERE url = report_url) THEN
                            INSERT INTO blacklisted_urls (url, status, threat_level) VALUES (report_url, report_status, report_threat_level);
                        ELSE
                            UPDATE blacklisted_urls SET status = report_status, threat_level = report_threat_level WHERE url = report_url;
                        END IF;
                        DELETE FROM virustotal_reports WHERE url = report_url AND status = report_status;
                    END IF;
                END IF;
            END LOOP;
        
            CLOSE cur;
          END;
        `;
        db.query(createProcedure, (err, result) => {
            if (err) {
                console.error('Error creating procedure:', err);
                return;
            }
            console.log('Procedure created successfully');
        });
      });

      // Create event if it doesn't exist
      const createEvent = `
        CREATE EVENT IF NOT EXISTS process_virustotal_reports_event
        ON SCHEDULE EVERY 10 SECOND
        DO
        CALL process_virustotal_reports();
      `;
      db.query(createEvent, (err, result) => {
        if (err) {
            console.error('Error creating event:', err);
            return;
        }
        console.log('Event created or already exists:', result);
      });
    });

    db.query('DROP PROCEDURE IF EXISTS delete_unrated_urls_if_exists', (err, result) => {
      if (err) {
          console.error('Error dropping existing procedure:', err);
          return;
      }
  
      // Create stored procedure
      const createProcedure = `
          CREATE PROCEDURE delete_unrated_urls_if_exists()
          BEGIN
              DECLARE url_to_delete VARCHAR(255);
              DECLARE done INT DEFAULT FALSE;
              DECLARE cur CURSOR FOR SELECT url FROM unrated_reports;
              DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
              
              OPEN cur;
              
              read_loop: LOOP
                  FETCH cur INTO url_to_delete;
                  IF done THEN
                      LEAVE read_loop;
                  END IF;
                  
                  -- Check if the URL exists in whitelisted_urls or blacklisted_urls
                  IF EXISTS (SELECT 1 FROM whitelisted_urls WHERE url = url_to_delete) OR 
                     EXISTS (SELECT 1 FROM blacklisted_urls WHERE url = url_to_delete) THEN
                      DELETE FROM unrated_reports WHERE url = url_to_delete;
                  END IF;
              END LOOP;
              
              CLOSE cur;
          END;
      `;
      db.query(createProcedure, (err, result) => {
          if (err) {
              console.error('Error creating procedure:', err);
              return;
          }
          console.log('Procedure for deleting unrated URLs created successfully');
      });
      const createEvent = `
        CREATE EVENT IF NOT EXISTS process_unrated_reports_event
        ON SCHEDULE EVERY 10 SECOND
        DO
        CALL delete_unrated_urls_if_exists();
      `;
      db.query(createEvent, (err, result) => {
        if (err) {
            console.error('Error creating event:', err);
            return;
        }
        console.log('Event created or already exists:', result);
      });
    });

    // Create event if it doesn't exist
    const createEvent = `
      CREATE EVENT IF NOT EXISTS process_incoming_reports_event
      ON SCHEDULE EVERY 10 SECOND
      DO
      CALL process_incoming_reports();
    `;
    db.query(createEvent, (err, result) => {
      if (err) {
        console.error('Error creating event:', err);
        return;
      }
      console.log('Event created or already exists:', result);
    });
  });
};

// POST endpoint to add data to incoming_reports
app.post('/add-data', (req, res) => {
  const { url, status, threat_level } = req.body;

  const sql = 'INSERT INTO incoming_reports (url, status, threat_level) VALUES (?, ?, ?)';
  db.query(sql, [url, status, threat_level], (err, result) => {
    if (err) {
      console.error('Error adding data to incoming_reports:', err);
      res.status(500).json({ error: 'Failed to add data to incoming_reports' });
      return;
    }
    console.log('Data added to incoming_reports:', result);
    res.status(200).json({ message: 'Data added successfully to incoming_reports' });
  });
});

// POST endpoint to add data to incoming_reports
app.post('/add-data-virustotal', (req, res) => {
  const { url, status, threat_level } = req.body;

  const sql = 'INSERT INTO virustotal_reports (url, status, threat_level) VALUES (?, ?, ?)';
  db.query(sql, [url, status, threat_level], (err, result) => {
    if (err) {
      console.error('Error adding data to virustotal_reports:', err);
      res.status(500).json({ error: 'Failed to add data to virustotal_reports' });
      return;
    }
    console.log('Data added to virustotal_reports:', result);
    res.status(200).json({ message: 'Data added successfully to virustotal_reports' });
  });
});

// POST endpoint to add data to incoming_reports
app.post('/add-data-unrated', (req, res) => {
  const { url, status } = req.body;

  const sql = 'INSERT INTO unrated_reports (url, status) VALUES (?, ?)';
  db.query(sql, [url, status], (err, result) => {
    if (err) {
      console.error('Error adding data to unrated_reports:', err);
      res.status(500).json({ error: 'Failed to add data to unrated_reports' });
      return;
    }
    console.log('Data added to unrated_reports:', result);
    res.status(200).json({ message: 'Data added successfully to unrated_reports' });
  });
});

// Endpoint to check URL against whitelisted_reports
app.get('/check-whitelist', (req, res) => {
  const { url } = req.query;

  const query = 'SELECT * FROM whitelisted_urls WHERE url = ?';
  db.query(query, [url], (err, results) => {
    if (err) {
      console.error('Error checking whitelist:', err);
      return res.status(500).json({ error: 'Failed to check whitelist' });
    }
    res.json({ isWhitelisted: results.length > 0 });
  });
});

// Endpoint to check URL against blacklisted_urls
app.get('/check-blacklist', (req, res) => {
  const { url } = req.query;

  const query = 'SELECT * FROM blacklisted_urls WHERE url = ?';
  db.query(query, [url], (err, results) => {
    if (err) {
      console.error('Error checking blacklist:', err);
      return res.status(500).json({ error: 'Failed to check blacklist' });
    }
    res.json({ isBlacklisted: results.length > 0 });
  });
});

// Endpoint to check URL against whitelisted_reports
app.get('/check-unrated', (req, res) => {
  const { url } = req.query;

  const query = 'SELECT * FROM unrated_reports WHERE url = ?';
  db.query(query, [url], (err, results) => {
    if (err) {
      console.error('Error checking unrated_reports:', err);
      return res.status(500).json({ error: 'Failed to check unrated_reports' });
    }
    res.json({ isUnrated: results.length > 0 });
  });
});

// Endpoint to check threat_level for a URL in blacklisted_urls
app.get('/check-threat-level', (req, res) => {
  const { url } = req.query;

  const query = 'SELECT threat_level FROM blacklisted_urls WHERE url = ?';
  db.query(query, [url], (err, results) => {
    if (err) {
      console.error('Error checking threat level:', err);
      return res.status(500).json({ error: 'Failed to check threat level' });
    }
    if (results.length > 0) {
      res.json({ threatLevel: results[0].threat_level });
    } else {
      res.json({ threatLevel: 'URL not found in blacklist' });
    }
  });
});

// Endpoint to get data from users table
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.json({ success: false, message: 'Invalid username or password' });
    }
  });
});

// Endpoint to retrieve all data from whitelisted_urls
app.get('/whitelisted-urls', (req, res) => {
  const query = 'SELECT * FROM whitelisted_urls';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching whitelisted URLs:', err);
      return res.status(500).json({ error: 'Failed to fetch whitelisted URLs' });
    }
    res.json(results);
  });
});

// Endpoint to retrieve all data from blacklisted_urls
app.get('/blacklisted-urls', (req, res) => {
  const query = 'SELECT * FROM blacklisted_urls';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching blacklisted URLs:', err);
      return res.status(500).json({ error: 'Failed to fetch blacklisted URLs' });
    }
    res.json(results);
  });
});


// Connect to the database
connectToDatabase();

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
