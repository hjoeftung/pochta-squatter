# Pochta Squatter

Pochta Squatter is a simple parsing utility that 
checks for domains that may potentially infringe 
Russian Post's trademarks

## Installation

Run ```docker-compose build``` to install the app. 
You will need to have Docker and Docker Compose to be
installed on your machine.

## Usage
Run ```docker-compose up``` to get the servers running. 
The app will be available at http://localhost.

API is on http://localhost/api/domains. Only two
queries are supported for now: 
- http://localhost/api/domains/?fmt=json - will return JSON
with a list of potentially dangerous domains;
- http://localhost/api/domains/?fmt=csv - will return a link
  to CSV file with potentially dangerous domains.


## License

[MIT] (https://choosealicense.com/licenses/mit/)
