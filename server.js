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
      CREATE TABLE IF NOT EXISTS whitelisted_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30)
      );
    `;
    db.query(createWhitelistedReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating whitelisted_reports table:', err);
        return;
      }
      console.log('whitelisted_reports table created or already exists:', result);
    });

    const createBlacklistedUrlsTable = `
      CREATE TABLE IF NOT EXISTS blacklisted_urls (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(255),
        status VARCHAR(30)
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
        status VARCHAR(30)
      );
    `;
    db.query(createIncomingReportsTable, (err, result) => {
      if (err) {
        console.error('Error creating incoming_reports table:', err);
        return;
      }
      console.log('incoming_reports table created or already exists:', result);
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
          DECLARE cur CURSOR FOR 
              SELECT url, status
              FROM incoming_reports
              GROUP BY url, status
              HAVING COUNT(*) >= 10;

          DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

          OPEN cur;

          read_loop: LOOP
              FETCH cur INTO report_url, report_status;
              IF done THEN
                  LEAVE read_loop;
              END IF;

              IF report_status = 'benign' THEN
                  IF NOT EXISTS (SELECT 1 FROM whitelisted_reports WHERE url = report_url AND status = report_status) THEN
                      INSERT INTO whitelisted_reports (url, status) VALUES (report_url, report_status);
                  END IF;
              ELSE
                  IF NOT EXISTS (SELECT 1 FROM blacklisted_urls WHERE url = report_url AND status = report_status) THEN
                      INSERT INTO blacklisted_urls (url, status) VALUES (report_url, report_status);
                  END IF;
              END IF;

              DELETE FROM incoming_reports WHERE url = report_url AND status = report_status;
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
      CREATE EVENT IF NOT EXISTS process_incoming_reports_event
      ON SCHEDULE EVERY 1 MINUTE
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
  const { url, status } = req.body;

  const sql = 'INSERT INTO incoming_reports (url, status) VALUES (?, ?)';
  db.query(sql, [url, status], (err, result) => {
    if (err) {
      console.error('Error adding data to incoming_reports:', err);
      res.status(500).json({ error: 'Failed to add data to incoming_reports' });
      return;
    }
    console.log('Data added to incoming_reports:', result);
    res.status(200).json({ message: 'Data added successfully to incoming_reports' });
  });
});

// Endpoint to check URL against whitelisted_reports
app.get('/check-whitelist', (req, res) => {
  const { url } = req.query;

  const query = 'SELECT * FROM whitelisted_reports WHERE url = ?';
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

// Connect to the database
connectToDatabase();

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
