# Pochta Squatter

Pochta Squatter is a simple parsing utility that 
checks for domains that may potentially infringe 
Russian Post's trademarks

## Installation

Currently, installation with pip is unavailable.
Please clone the repository with ```git clone 
https://github.com/hjoeftung/pochta-squatter```.

## Usage

```python main.py upload``` - make initial search
for potentially infringing domains and populate 
the database with results. If you use program 
for the first time start with this command.

```python main.py update``` - make a subsequent
search and refresh results in the database.

```python main.py export``` - export the results
in the database to a .csv file.

## License

[MIT] (https://choosealicense.com/licenses/mit/)
