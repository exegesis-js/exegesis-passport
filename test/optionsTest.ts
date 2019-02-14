import { expect } from 'chai';
import http from 'http';
import 'mocha';
import { Passport } from 'passport';
import { Strategy } from 'passport-strategy';
import { CallbackAuthenticator } from 'exegesis';
import pb from 'promise-breaker';
import exegesisPassport from '../src';

class OptionsStrategy extends Strategy {
    constructor() {
        super();
    }

    authenticate(_req: http.IncomingMessage, options: any) {
        this.success(options.defaultUser, null);
    }
}

const USER = {name: 'dave'};

describe('options', function() {

    it('should pass options to passport strategy using passport', async function() {
        const passport = new Passport();
        const optionsStrategy = new OptionsStrategy();
        passport.use('options', optionsStrategy);
        const req : any = {};
        const pluginContext : any = {req};

        const authenticator : CallbackAuthenticator =
            exegesisPassport(passport, 'options', {passportOptions: {defaultUser: USER}});

        const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));
        expect(result).to.eql({
            type: 'success',
            user: USER,
            roles: undefined,
            scopes: undefined
        });
    });

    it('should pass options to passport strategy without passport', async function() {
        const optionsStrategy = new OptionsStrategy();
        const req : any = {};
        const pluginContext : any = {req};

        const authenticator : CallbackAuthenticator =
            exegesisPassport(optionsStrategy, {passportOptions: {defaultUser: USER}});

        const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));
        expect(result).to.eql({
            type: 'success',
            user: USER,
            roles: undefined,
            scopes: undefined
        });
    });

});