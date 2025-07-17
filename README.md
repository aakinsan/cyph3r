# cyph3r

This project was created to assist with the automation of key generation, key splitting and encryption with PGP.

It consists of the following modules:

- Key/Password/URL-Safe string generation module.
- Key Splitting and Reconstruction module that supports Shamir Secret Sharing (SSS) and XOR Operation.
- Data Encryption/Decryption Module using AES-GCM and AES-CBC.
- A module that combines all the operation performed above and encrypts the artefact using PGP.

## Dependencies and Usage (in the development environment)

### Dependencies
1. Install node - https://github.com/nvm-sh/nvm?tab=readme-ov-file#install--update-script

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash

export NVM_DIR="$([ -z "${XDG_CONFIG_HOME-}" ] && printf %s "${HOME}/.nvm" || printf %s "${XDG_CONFIG_HOME}/nvm")"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm

nvm install node

```

2. Install app dependencies

```bash
pip install -r requirements.txt
```

3. Install tailwind dependencies
```bash 
python manage.py tailwind install
```

4. Install Redis Cache Server
```bash
sudo apt install redis-server

sudo systemctl start redis-server

sudo systemctl enable redis-server
```

5. Migrate model to sqlite database
```bash
python manage.py migrate
```

6. Generate Django secret key and pass it to the DJANGO_DEV_SECRET_KEY environment variable
```bash
 export DJANGO_DEV_SECRET_KEY="$(python3 -c 'import django.utils.crypto; print(django.utils.crypto.get_random_string(50, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-="))')"
 ```

### Usage
Open 2 terminals and enter the following in each one

1. Start the Django dev server. By default it runs on 127.0.0.1:8000

```bash
python manage.py runserver [0.0.0.0:8080]
```


## License
This project is licensed under the MIT License - see the LICENSE file for details.