import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";

interface IPayload {
  sub: string;
}

export function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
) {
  // receber o token
  const authToken = request.headers.authorization;

  //validar se token esta preenchido
  if (!authToken) {
    return response.status(401).end();
  }

  const [, token] = authToken.split(" ");

  try {
    //validar se token é valido
    const { sub } = verify(
      token,
      "31507df5a899f68469a6c38e11441382"
    ) as IPayload;

    //recuperar informações do usuário
    request.user_id = sub;

    return next();
  } catch (error) {
    return response.status(401).end();
  }
}
