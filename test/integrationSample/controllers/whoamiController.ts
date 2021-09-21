import { ExegesisContext } from "exegesis";

export function whoami(context: ExegesisContext) {
  return context.security as any;
}
