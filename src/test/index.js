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
