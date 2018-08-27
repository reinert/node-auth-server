require('dotenv').load()

const cookieParser = require('cookie-parser')
const cors = require('cors')
const express = require('express')
const expJwt = require('express-jwt')
const fs = require('fs')
const helmet = require('helmet')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')
const uuidv4 = require('uuid/v4')

const { decrypt, encrypt } = require('./encryption')

const LOGGER = require('./logger')

const JWT_ALGORITHM = 'RS256'
const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY)
const PUBLIC_KEY = fs.readFileSync(process.env.PUBLIC_KEY)

function isHeaderStrategy() {
  return process.env.STRATEGY && process.env.STRATEGY.toUpperCase() === 'HEADER'
}

function checkCredentials (req, res, next) {
  // TODO: implement credential verification logic
  req.sub = 'guest'

  return next()
}

function setAccessToken (req, res, next) {
  const now = Date.now()
  const accessExp = Math.floor(now / 1000) + parseInt(process.env.ACCESS_TOKEN_EXP)
  const refreshExp = parseInt(process.env.REFRESH_TOKEN_EXP)
  const refreshMaxAge = refreshExp * 1000
  const pairId = uuidv4()
  const xsrfToken = uuidv4()

  res.locals.now = now
  res.locals.accessExp = accessExp
  res.locals.refreshExp = Math.floor(now / 1000) + refreshExp
  res.locals.refreshMaxAge = refreshMaxAge
  res.locals.pairId = pairId
  res.locals.xsrfToken = xsrfToken

  const payload = {
    sub: req.sub,
    exp: accessExp,
    iss: process.env.ISSUER,
    aud: req.query.aud,
    pid: pairId,
    xid: xsrfToken
  }

  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: JWT_ALGORITHM })

  LOGGER.debug('Signed access token with payload:', payload)

  if (isHeaderStrategy()) {
    // return the Access Token via X-Access-Token header
    res.set('X-Access-Token', token)

    LOGGER.verbose('Set access token to X-Access-Token header')
  } else {
    // return the Access Token via Cookie by default
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      maxAge: refreshMaxAge
    }

    if (process.env.DOMAIN) cookieOptions.domain = process.env.DOMAIN

    res.cookie('ACCESS-TOKEN', token, cookieOptions)

    LOGGER.verbose('Set access token to ACCESS-TOKEN cookie')
  }

  next()
}

function setRefreshToken (req, res, next) {
  const payload = {
    sub: req.sub,
    exp: res.locals.refreshExp,
    nbf: res.locals.accessExp,
    iss: process.env.ISSUER,
    aud: req.query.aud,
    pid: res.locals.pairId
  }

  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: JWT_ALGORITHM })

  LOGGER.debug('Signed refresh token with payload:', payload)

  const enc_token = encrypt(token)

  LOGGER.debug('Encrypted refresh token:', enc_token)

  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: res.locals.refreshMaxAge
  }

  res.cookie('REFRESH-TOKEN', enc_token, cookieOptions)

  LOGGER.verbose('Set encrypted refresh token to REFRESH-TOKEN cookie')

  next()
}

function setXsrfToken (req, res, next) {
  const cookieOptions = {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: res.locals.accessExp * 1000
  }

  res.cookie('XSRF-TOKEN', res.locals.xsrfToken, cookieOptions)

  LOGGER.verbose('Set XSRF token to XSRF-TOKEN cookie')

  next()
}

function getAccessToken (req) {
  if (isHeaderStrategy()) {
    if (req.headers.authorization) {
      const [ scheme, credentials ] = req.headers.authorization.split(' ')

      if (scheme === 'Bearer') {
        LOGGER.verbose(`Found access token in Authorization header: ${req.cookies['ACCESS-TOKEN']}`)

        req.accessToken = credentials
      }
    }
  } else if (req.cookies['ACCESS-TOKEN']) {
    LOGGER.verbose(`Found ACCESS-TOKEN cookie: ${req.cookies['ACCESS-TOKEN']}`)

    req.accessToken = req.cookies['ACCESS-TOKEN']
  }

  if (!req.accessToken) LOGGER.verbose('Access token not found')

  return req.accessToken
}

function getRefreshToken (req) {
  if (req.cookies['REFRESH-TOKEN']) {
    LOGGER.verbose(`Found REFRESH-TOKEN cookie: ${req.cookies['REFRESH-TOKEN']}`)

    const token = decrypt(req.cookies['REFRESH-TOKEN'])

    LOGGER.debug('Decrypted refresh token cookie:', token)

    req.refreshToken = token
  }

  if (!req.refreshToken) LOGGER.verbose('REFRESH-TOKEN cookie not found')

  return req.refreshToken
}

function checkPairId (req, res, next) {
  const at = jwt.decode(req.accessToken)
  const rt = jwt.decode(req.refreshToken)

  if (at.pid !== rt.pid) {
    LOGGER.error(`[CAUTION] Attempt to refresh with a non matching token pair:`
      + `\n  AT: ${req.accessToken}\n  RT: ${req.refreshToken}`)

    const error = new Error('Token pair do not match')
    error.status = 401

    return next(error)
  }

  next()
}

function delTokens (req, res, next) {
  if (!isHeaderStrategy()) {
    res.clearCookie('ACCESS-TOKEN', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax'
    })

    LOGGER.verbose('ACCESS-TOKEN cookie cleared')
  }

  res.clearCookie('REFRESH-TOKEN', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict'
  })

  LOGGER.verbose('REFRESH-TOKEN cookie cleared')

  res.clearCookie('XSRF-TOKEN', {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax'
  })

  LOGGER.verbose('XSRF-TOKEN cookie cleared')

  next()
}

function sendOk (req, res) {
  return res.locals.payload
    ? res.send(res.locals.payload)
    : res.sendStatus(204)
}

function notFoundHandler (req, res, next) {
  let err = new Error();
  err.status = 404;
  next(err);
}

function errorHandler (err, req, res, next) {
  let statusProp = Number.isInteger(err.statusCode)
    ? 'statusCode'
    : 'status'

  if (err[statusProp]) {
    if (err.message) {
      LOGGER.error(err.message, err)
      res.status(err[statusProp]).send(err.message)
    } else {
      LOGGER.error(err)
      res.sendStatus(err[statusProp])
    }

    return
  }

  console.error(err)

  // tweak in order to be caught by winston
  err.msg = err.message
  process.emit('uncaughtException', err)

  res.sendStatus(500)
}

function sendText (res, text) {
  res.set('Content-Type', 'text/plain')
  res.send(text)
}

function createServer (checkCredentials) {
  return express()
    .use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev', { 'stream': LOGGER.stream }))
    .use(cors({
      origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true,  // this is insecure; must be updated to the production domain
      credentials: true,
      optionsSuccessStatus: 200
    }))
    .use(helmet())
    .get('/algorithm', (req, res) => sendText(res, JWT_ALGORITHM))
    .get('/public-key', (req, res) => sendText(res, PUBLIC_KEY))
    .get('/signin',
      checkCredentials,
      setAccessToken,
      setRefreshToken,
      setXsrfToken,
      sendOk
    )
    .use(cookieParser())
    .get('/refresh',
      expJwt({ secret: PUBLIC_KEY, algorithms: [ JWT_ALGORITHM ], getToken: getAccessToken, ignoreExpiration: true }),
      expJwt({ secret: PUBLIC_KEY, algorithms: [ JWT_ALGORITHM ], getToken: getRefreshToken }),
      checkPairId,
      setAccessToken,
      setRefreshToken,
      setXsrfToken,
      sendOk
    )
    .get('/signout',
      delTokens,
      sendOk
    )
    .get('*', notFoundHandler)
    .use(errorHandler)
}

module.exports = { createServer, LOGGER }
