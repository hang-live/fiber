-- Hobbies Table
CREATE TABLE IF NOT EXISTS hobbies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT
);

-- Third-spaces Table
CREATE TABLE IF NOT EXISTS third_spaces (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT
);

-- Locations Table
CREATE TABLE IF NOT EXISTS locations (
    id SERIAL PRIMARY KEY,
    timezone VARCHAR(50),
    address TEXT,
    city VARCHAR(100),
    state VARCHAR(100),
    country VARCHAR(100),
    zip_code VARCHAR(20)
);

-- Events Table
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_updated TIMESTAMP,
    date_deleted TIMESTAMP,
    date_scheduled TIMESTAMP,
    location_id INTEGER REFERENCES locations(id),
    description TEXT,
    name VARCHAR(255) NOT NULL
);

-- Ratings Table
CREATE TABLE IF NOT EXISTS ratings (
    id SERIAL PRIMARY KEY,
    sending_user_id INTEGER,
    receiving_user_id INTEGER NOT NULL,
    event_id INTEGER REFERENCES events(id),
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rating BOOLEAN
);

-- Attendance Table
CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    event_id INTEGER REFERENCES events(id),
    attendance BOOLEAN
);
