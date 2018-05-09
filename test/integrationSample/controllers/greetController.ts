import { ExegesisContext } from "exegesis";

export function greetGet(context: ExegesisContext) {
    const {name} = context.params.query;
    return {greeting: `Hello, ${name}!`};
}