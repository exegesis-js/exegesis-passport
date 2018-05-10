# exegesis-passport

[![NPM version](https://badge.fury.io/js/exegesis-passport.svg)](https://npmjs.org/package/exegesis-passport)
[![Build Status](https://travis-ci.org/exegesis-js/exegesis-passport.svg)](https://travis-ci.org/exegesis-js/exegesis-passport)
[![Coverage Status](https://coveralls.io/repos/exegesis-js/exegesis-passport/badge.svg)](https://coveralls.io/r/exegesis-js/exegesis-passport)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)

This package lets you use passport to authenticate requests in Exegesis.

```js
import passport from 'passport';
import * as exegesisExpress from 'exegesis-express';
import exegesisPassport from 'exegesis-passport;
import { BasicStrategy } from 'passport-http';

passport.use('basic', new BasicStrategy((username, password, done) => {
    if(password === 'secret') {
        done(null, {user: username});
    } else {
        done(null, false);
    }
}));

async function createServer() {
    const app = express();

    app.use(passport.initialize());

    app.use(await exegesisExpress.middleware(
        path.resolve(__dirname, './openapi.yaml'),
        {
            // Other options go here...
            authenticators: {
                // Authenticate the "basicAuth" security scheme using passport's 'basic' strategy.
                basicAuth: exegesisPassport('basic'),
                // Uses Passport's build-in 'session' strategy.
                sessionToken: exegesisPassport('session')
            }
        }
    ));

    const server = http.createServer(app);
    server.listen(3000);
}
```

## API

### exegesisPassport(passport, strategyName[[, converter], options])

Returns an Exegesis authenticator that will authenticate against the given strategyName.
This will not set the user in the session.

`converter` is a `function(user, pluginContext)` which takes in the user
authenticated by passport and returns a `{user, roles, scopes}` object for
Exegesis.

If `options` if provided, this will be passed to the passport strategy when
it is run.

### exegesisPassport(strategy[[, converter], options])

You can pass a Passport strategy directly to Exegesis to use the strategy without even
having Passport installed:

```js
const basicStrategy = new BasicStrategy((username, password, done) => {
    if(password === 'secret') {
        done(null, {user: username});
    } else {
        done(null, false);
    }
});

exegesisOptions.authenticators = {
    basicAuth: exegesisPassport(basicStrategy)
}
```

`converter` is a `function(user, pluginContext)` which takes in the user
authenticated by passport and returns a `{user, roles, scopes}` object for
Exegesis.

If `options` if provided, this will be passed to the passport strategy when
it is run.

## Passport

Want to learn more about passport?  [API docs here](https://github.com/jwalton/passport-api-docs).