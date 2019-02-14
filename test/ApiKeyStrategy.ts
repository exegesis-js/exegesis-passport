import { Strategy } from 'passport-strategy';
import http from 'http';

// A passport strategy that aproves requests with a header named "apiKey"
// with the content "secret".
export default class ApiKeyStrategy extends Strategy {
    constructor() {
        super();
    }

    authenticate(req: http.IncomingMessage) {
        if(req.headers.apikey === 'secret') {
            this.success({username: 'jwalton', roles: ['role1']}, undefined);
        } else if(req.headers.apikey === 'redirect') {
            this.redirect('/login', 302);
        } else if(req.headers.apikey === 'pass') {
            this.pass();
        } else if(req.headers.apikey === 'error') {
            this.error(new Error("boom"));
        } else {
            this.fail(401);
        }
    }
}
