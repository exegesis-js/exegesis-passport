import { expect } from 'chai';
import http from 'http';
import 'mocha';
import { Passport } from 'passport';
import { Strategy } from 'passport-strategy';
import { CallbackAuthenticator } from 'exegesis';
import pb from 'promise-breaker';
import {default as exegesisPassport, Options} from '../src';

class ApiKeyStrategy extends Strategy {
    constructor() {
        super();
        this.name = 'apiKey';
    }

    authenticate(req: http.IncomingMessage) {
        if(req.headers.apikey === 'secret') {
            this.success({name: 'Sally'}, null);
        } else {
            (this as any).fail({message: "Bad key"});
        }
    }
}

function makeApiKeyAuthenticator(opts: Options = {}) {
    const passport = new Passport();
    const apiKeyStrategy = new ApiKeyStrategy();
    passport.use('apiKey', apiKeyStrategy);

    const authenticator : CallbackAuthenticator =
        exegesisPassport(passport, 'apiKey', opts);
    return authenticator;
}

class BasicAuthStrategy extends Strategy {
    constructor() {
        super();
        this.name = 'basic';
    }

    authenticate(req: http.IncomingMessage) {
        if(req.headers.authorization === 'Basic foo') {
            this.success({name: 'Sally'}, null);
        } else {
            this.fail('Basic', 401);
        }
    }
}

function makeBasicAuthAuthenticator(opts: Options = {}) {
    const passport = new Passport();
    const strategy = new BasicAuthStrategy();
    passport.use('basic', strategy);

    const authenticator : CallbackAuthenticator =
        exegesisPassport(passport, 'basic', opts);
    return authenticator;
}

describe('isPresent', function() {

    describe('explicit', function() {
        it('should explicitly detect missing credentials', async function() {
            const authenticator = makeApiKeyAuthenticator({
                isPresent(pluginContext) {
                    return !!pluginContext.req.headers.apikey;
                }
            });

            const pluginContext : any = {req: {
                headers: {}
            }};
            const missingResult = await pb.call((done: any) => authenticator(pluginContext, {}, done));
            expect(missingResult).to.eql({
                type: 'missing',
                message: 'Bad key',
                status: undefined
            });

            pluginContext.req.headers.apikey = 'bad';
            const invalidResult = await pb.call((done: any) => authenticator(pluginContext, {}, done));
            expect(invalidResult).to.eql({
                type: 'invalid',
                message: 'Bad key',
                status: undefined
            });

        });

        it('should work when `isPresent()` is full of lies', async function() {
            const authenticator = makeApiKeyAuthenticator({
                isPresent() {
                    // isPresent says false, but the authenticator is going to pass.
                    return false;
                }
            });

            const pluginContext : any = {req: {
                headers: {apikey: 'secret'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                type: 'success',
                user: {name: 'Sally'},
                roles: undefined,
                scopes: undefined
            });
        });
    });

    describe('apiKey', function() {
        it('should auto-detect missing credentials', async function() {
            const authenticator = makeApiKeyAuthenticator();

            const pluginContext : any = {req: {
                headers: {}
            }};
            const missingResult = await pb.call((done: any) => authenticator(pluginContext, {
                in: 'header',
                name: 'apiKey'
            }, done));
            expect(missingResult).to.eql({
                type: 'missing',
                message: 'Bad key',
                status: undefined
            });

            pluginContext.req.headers.apikey = 'bad';
            const invalidResult = await pb.call((done: any) => authenticator(pluginContext, {
                in: 'header',
                name: 'apiKey'
            }, done));
            expect(invalidResult).to.eql({
                type: 'invalid',
                message: 'Bad key',
                status: undefined
            });

        });

        it('should work when auto-detected credentials are there', async function() {
            const authenticator = makeApiKeyAuthenticator();
            const pluginContext : any = {req: {
                headers: {apikey: 'secret'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {
                in: 'header',
                name: 'apiKey'
            }, done));

            expect(result).to.eql({
                type: 'success',
                user: {name: 'Sally'},
                roles: undefined,
                scopes: undefined
            });
        });

        it('should auto-detect empty credentials as present', async function() {
            const authenticator = makeApiKeyAuthenticator();
            const pluginContext : any = {req: {
                headers: {apikey: ''}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {
                in: 'header',
                name: 'apiKey'
            }, done));

            expect(result).to.eql({
                type: 'invalid',
                message: 'Bad key',
                status: undefined
            });
        });
    });

    describe('basic', function() {
        it('should auto-detect missing credentials', async function() {
            const authenticator = makeBasicAuthAuthenticator();
            const pluginContext : any = {req: {
                headers: {}
            }};

            const missingResult = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'Basic'
            }, done));
            expect(missingResult).to.eql({
                type: 'missing',
                challenge: 'Basic',
                status: 401
            });

            pluginContext.req.headers.authorization = 'Basic bad';
            const invalidResult = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'Basic'
            }, done));
            expect(invalidResult).to.eql({
                type: 'invalid',
                challenge: 'Basic',
                status: 401
            });
        });

        it('should treat scheme as case-insensitive', async function() {
            const authenticator = makeBasicAuthAuthenticator();
            const pluginContext : any = {req: {
                headers: {}
            }};

            const missingResult = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'basic'
            }, done));
            expect(missingResult).to.eql({
                type: 'missing',
                challenge: 'Basic',
                status: 401
            });

            pluginContext.req.headers.authorization = 'BASIC foo';
            const invalidResult = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'basic'
            }, done));
            expect(invalidResult).to.eql({
                type: 'invalid',
                challenge: 'Basic',
                status: 401
            });
        });

        it('should auto-detect authorization header with wrong scheme', async function() {
            const authenticator = makeBasicAuthAuthenticator();
            const pluginContext : any = {req: {
                headers: {'authorization': 'Digest BLAHBLAHBLAH'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'Basic'
            }, done));

            expect(result).to.eql({
                type: 'missing',
                challenge: 'Basic',
                status: 401
            });
        });

        it('should work when auto-detected credentials are there', async function() {
            const authenticator = makeBasicAuthAuthenticator();
            const pluginContext : any = {req: {
                headers: {'authorization': 'Basic foo'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {
                scheme: 'Basic'
            }, done));

            expect(result).to.eql({
                type: 'success',
                user: {name: 'Sally'},
                roles: undefined,
                scopes: undefined
            });
        });

    });
});