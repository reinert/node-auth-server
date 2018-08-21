Express JWT authorization server ready to use

## Usage
```js
const { createServer, LOGGER } = require('../lib/index.js')

function checkCredentials (req, res, next) {
  const sub = req.get('encp')

  if (sub === 'guest') {
    LOGGER.info(`Successful login of user ${sub}`)

    req.sub = sub

    next()
    return
  }

  LOGGER.error(`Unsuccessful login of user ${sub}`)

  const err = new Error('Invalid credentials')
  err.status = 401
  next(err)
}

const server = createServer(checkCredentials)
server.listen(process.env.PORT, () => {
  LOGGER.info(`Authorization server started on port ${process.env.PORT}`)
})
```

## Development
Run with Docker:
```bash
docker run -v <host-project-path>:<container-project-path> -w <container-project-path> -p 127.0.0.1:<host-port>:<container-port> -it <node-image> sh
```

Example:
```bash
docker run -v /home/reinert/projects/auth:/home/auth -w /home/auth -p 127.0.0.1:3001:3001 -it node:alpine sh
```