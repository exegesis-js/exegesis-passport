import express from 'express';
import http from 'http';
import * as path from 'path';
import { makeFetch } from 'supertest-fetch';
import * as exegesis from 'exegesis';
import * as exegesisExpress from 'exegesis-express';
import exegesisPassport, { PassportToExegesisRolesFn, PassportToExegesisResult } from '../src';
import { Passport } from 'passport';
import ApiKeyStrategy from './ApiKeyStrategy';
import SessionStrategy from './SessionStrategy';

const passport = new Passport();

function withObj(obj : any) {
    return obj ? 'with' : 'without';
}

async function createServer(withPassport: boolean, converter?: PassportToExegesisRolesFn) {
    const apiKeyStrategy = new ApiKeyStrategy();
    const sessionStragegy = new SessionStrategy();

    passport.use('api-key', apiKeyStrategy);
    passport.use('session', sessionStragegy);

    const apiAuthenticator: exegesis.Authenticator = withPassport
        ? exegesisPassport(passport, 'api-key', converter)
        : exegesisPassport(apiKeyStrategy, converter);

    const sessionAuthenticator: exegesis.Authenticator = withPassport
        ? exegesisPassport(passport, 'session', converter)
        : exegesisPassport(sessionStragegy, converter);

    const options : exegesisExpress.ExegesisOptions = {
        controllers: path.resolve(__dirname, './integrationSample/controllers'),
        authenticators: {
            apiKey: apiAuthenticator,
            session: sessionAuthenticator
        },
        controllersPattern: "**/*.ts"
    };

    const exegesisMiddleware = await exegesisExpress.middleware(
        path.resolve(__dirname, './integrationSample/openapi.yaml'),
        options
    );

    const app = express();
    if(withPassport) {
        app.use(passport.initialize());
    }

    app.use(exegesisMiddleware);

    app.use((_req, res) => {
        res.status(404).json({message: `Not found`});
    });

    app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        res.status(500).json({message: `Internal error: ${err.message}`});
    });

    return http.createServer(app);
}

function converterFn(user: any) : PassportToExegesisResult {
    return {
        user: user,
        roles: ['a'],
        scopes: ['b']
    };
}

describe('integration', function() {
    for(const withPassport of [true, false]) {
        for(const converter of [converterFn, undefined]) {
            describe(`${withObj(withPassport)} passport, ${withObj(converter)} conveter`, function() {
                beforeEach(async function() {
                    this.server = await createServer(withPassport, converter);
                });

                afterEach(function() {
                    if(this.server) {this.server.close();}
                });

                it('should authenticate a call to the API', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {headers: {apiKey: 'secret'}})
                        .expect(200)
                        .expect('content-type', 'application/json')
                        .expectBody({greeting: 'Hello, Jason!'});
                });

                it('should deny a call to the API with invalid api key', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {headers: {apiKey: 'nope'}})
                        .expect(401);
                });

                it('should deny a call to the API with missing api key', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`)
                        .expect(401);
                });

                // TODO: Should it really?
                it('should honor a redirect', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {
                        headers: {apiKey: 'redirect'},
                        redirect: 'manual'
                    })
                        .expect(302)
                        .expectHeader('Location', /^.*\/login$/);
                });

                it('should treat "pass"es like failures', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {headers: {apiKey: 'pass'}})
                        .expect(401);
                });

                it('should pass along errors', async function() {
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {headers: {apiKey: 'error'}})
                        .expect(500);
                });

                it('should convert user from strategy into an exegesis user', async function() {
                    const expectedUser = {username: 'jwalton', roles: ['role1']};
                    const expectedWithoutConverter = {
                        apiKey: {
                            type: 'success',
                            user: expectedUser,
                            roles: ['role1']
                        }
                    };

                    const expectedWithConverter = {
                        apiKey: {
                            type: 'success',
                            user: expectedUser,
                            roles: ['a'],
                            scopes: ['b']
                        }
                    };

                    const expected = !!converter ? expectedWithConverter : expectedWithoutConverter;
                    const fetch = makeFetch(this.server);
                    await fetch(`/whoami`, {headers: {apiKey: 'secret'}})
                        .expect(200, expected);
                });

                it('should authenticate a call to the API with session strategy', async function() {
                    // Session strategy does weird things.
                    const fetch = makeFetch(this.server);
                    await fetch(`/greet?name=Jason`, {headers: {session: 'jwalton'}})
                        .expect(200)
                        .expect('content-type', 'application/json')
                        .expectBody({greeting: 'Hello, Jason!'});
                });

            });
        }
    }
});