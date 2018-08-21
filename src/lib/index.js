require('dotenv').load()

const cookieParser = require('cookie-parser')
const cors = require('cors')
const express = require('express')
const expJwt = require('express-jwt')
const fs = require('fs')
const helmet = require('helmet')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')

const { decrypt, encrypt } = require('./encryption')

const LOGGER = require('./logger')

const JWT_ALGORITHM = 'RS256'
const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY)
const PUBLIC_KEY = fs.readFileSync(process.env.PUBLIC_KEY)

function checkCredentials (req, res, next) {
  // TODO: implement credential verification logic
  req.sub = 'guest'

  return next()
}

function setAccessToken (req, res, next) {
  const payload = {
    sub: req.sub,
    exp: Math.floor(Date.now() / 1000) + parseInt(process.env.ACCESS_TOKEN_EXP),
    iss: process.env.ISSUER,
    aud: req.query.aud
  }

  const token = jwt.sign(payload, PRIVATE_KEY, {algorithm: JWT_ALGORITHM})

  LOGGER.debug('Signed access token with payload:', payload)

  res.set('X-Access-Token', token)

  LOGGER.verbose('Set access token to X-Access-Token header')

  next()
}

function setRefreshToken (req, res, next) {
  let exp = parseInt(process.env.REFRESH_TOKEN_EXP)

  const payload = {
    sub: req.sub,
    exp: Math.floor(Date.now() / 1000) + exp,
    iss: process.env.ISSUER,
    aud: req.query.aud
  }

  const token = jwt.sign(payload, PRIVATE_KEY, {algorithm: JWT_ALGORITHM})

  LOGGER.debug('Signed refresh token with payload:', payload)

  const enc_token = encrypt(token)

  LOGGER.debug('Encrypted refresh token:', enc_token)

  const cookieOptions = {httpOnly: true, maxAge: exp * 1000}

  res.cookie('refresh_token', enc_token, cookieOptions)

  LOGGER.verbose('Set encrypted refresh token to refresh_token cookie')

  next()
}

function getRefreshToken (req) {
  if (req.cookies.refresh_token) {
    LOGGER.verbose(`Found refresh_token cookie: ${req.cookies.refresh_token}`)

    const token = decrypt(req.cookies.refresh_token)

    LOGGER.debug('Decrypted refresh token cookie:', token)

    return token
  }

  LOGGER.verbose('refresh_token cookie not found')

  return null
}

function delRefreshToken (req, res, next) {
  res.clearCookie('refresh_token', { httpOnly: true })

  LOGGER.verbose('refresh_token cookie cleared')

  next()
}

function sendOk(req, res) {
  res.sendStatus(200)
}

function errorHandler(err, req, res, next) {
  let statusProp = Number.isInteger(err.statusCode)
    ? 'statusCode'
    : 'status'

  if (err[statusProp]) {
    LOGGER.error(err.message, err)
    res.status(err[statusProp]).send(err.message)
    return
  }

  // tweak in order to be caught by winston
  err.msg = err.message
  process.emit('uncaughtException', err)

  res.sendStatus(500)
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
    .get('/public-key', (req, res) => res.send(PUBLIC_KEY))
    .get('/signin',
      checkCredentials,
      setAccessToken,
      setRefreshToken,
      sendOk
    )
    .use(cookieParser())
    .get('/refresh',
      expJwt({ secret: PUBLIC_KEY, algorithms: [ JWT_ALGORITHM ] }),
      expJwt({ secret: PUBLIC_KEY, algorithms: [ JWT_ALGORITHM ], getToken: getRefreshToken }),
      setAccessToken,
      setRefreshToken,
      sendOk
    )
    .get('/signout',
      delRefreshToken,
      sendOk
    )
    .use(errorHandler)
}

module.exports = { createServer, LOGGER }
