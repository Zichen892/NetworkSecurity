# Security policy

Please report a flaw in the tool through a private GitHub security advisory or a private contact method on the maintainer's GitHub profile. Share a minimal synthetic reproduction. Do not attach live phishing URLs, credentials, private captures, or user data to public issues.

The classifier reads local CSV files and the URL review reads local text files. Neither makes network requests or acts as a production URL reputation service. MongoDB access is separate, opt-in, and requires `MONGO_DB_URL`; never commit the connection string or a `.env` file.
