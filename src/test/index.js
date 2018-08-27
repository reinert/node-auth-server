const { createServer, LOGGER } = require('../lib/index.js')

const http = require('http')

function checkCredentials (req, res, next) {
  const sub = req.get('User')

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

function remoteCheckCredentials (req, res, next) {
  const opt = { headers: { 'Authorization': req.headers.authorization } }
  http.get('http://localhost:3001', opt, resp => {
    if (resp.statusCode !== 200) {
      const error = new Error()
      error.status = resp.statusCode
      return next(error)
    }

    resp.setEncoding('utf8')
    let rawData = ''
    resp.on('data', chunck => rawData += chunck)
    resp.on('end', () => {
      res.locals.payload = rawData
      next()
    })
  })
}

const server = createServer(checkCredentials)
server.listen(process.env.PORT, () => {
  LOGGER.info(`Authorization server started on port ${process.env.PORT}`)
})
