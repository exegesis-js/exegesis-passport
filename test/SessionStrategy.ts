import { Strategy } from 'passport-strategy';
import http from 'http';

export default class SessionStrategy extends Strategy {
    constructor() {
        super();
    }

    authenticate(req: http.IncomingMessage) {
        // Default session strategy from passport does essentially this.
        if(req.headers.session === 'jwalton') {
            (req as any).user = {username: 'jwalton', roles: ['role1']};
        }
        this.pass();
    }
}
