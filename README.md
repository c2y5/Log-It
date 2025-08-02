# Log-It API

An API for developers to log and manage their application logs.

\* The authorization header is called ``LogIt-Authorization`` and it uses JWT tokens

![LogItBanner](./static/LogItBanner.png)

---

## Features

* JWT Authentication from `LogIt-Authorization` header
* Advanced search with regex, date and other filters
* Bulk Logging for batching log submissions
* Export Logs in JSON or CSV
* IP blacklist per dev key
* Discord webhook support

---

## Documentation

Full API documentation @ https://logit.amsky.xyz

---

## Host it yourself

Clone the repository & install the requirements

```bash
git clone https://github.com/c2y5/Log-It
cd Log-It
pip install -r requirements.txt
```

Configure ``.env``
- Copy the contents of ``.env.example`` and create a file ``.env`` in ./api folder
- Set the ``MONGO_URI`` to your MongoDB Atlas URI
- Update ``JWT_SECRET`` to a random string 

# License 

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

# Contributing

Feel free to submit issues or pull requests! Suggestions to improve **Log-It** are very welcome.