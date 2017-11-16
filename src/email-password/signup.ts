import { fromEvent, FunctionEvent } from 'graphcool-lib'
import { GraphQLClient } from 'graphql-request'
import * as bcrypt from 'bcryptjs'
import * as validator from 'validator'

interface User {
  id: string
}

interface EventData {
  email: string
  password: string
  name: string
}

const SALT_ROUNDS = 10

export default async (event: FunctionEvent<EventData>) => {
  console.log(event)

  try {
    const graphcool = fromEvent(event)
    const api = graphcool.api('simple/v1')

    const { email, password, name } = event.data

    if (!validator.isEmail(email)) {
      return { error: {
        code: 1,
        message: 'Not a valid email',
        userFacingMessage: 'Por favor insira um e-mail válido'
      }}
    }

    // check if user exists already
    const userExists: boolean = await getUser(api, email)
      .then(r => r.User !== null)
    if (userExists) {
      return {
        error: {
          code: 2,
          message: 'Email already in use',
          userFacingMessage: 'O e-mail inserido já está em uso'
        }
      }
    }

    // create password hash
    const salt = bcrypt.genSaltSync(SALT_ROUNDS)
    const hash = await bcrypt.hash(password, SALT_ROUNDS)

    // create new user
    const userId = await createGraphcoolUser(api, email, hash, name)

    // generate node token for new User node
    const token = await graphcool.generateNodeToken(userId, 'User')

    return { data: { id: userId, token } }
  } catch (e) {
    console.log(e)
    return {
      error: {
        code: 0,
        message: 'An unexpected error occured during signup.',
        userFacingMessage: `${e.toString()}`
      }
    }
  }
}

async function getUser(api: GraphQLClient, email: string): Promise<{ User }> {
  const query = `
    query getUser($email: String!) {
      User(email: $email) {
        id
      }
    }
  `

  const variables = {
    email,
  }

  return api.request<{ User }>(query, variables)
}

async function createGraphcoolUser(api: GraphQLClient, email: string, password: string, name: string): Promise<string> {
  const mutation = `
    mutation createGraphcoolUser($email: String!, $password: String!, $name: String!) {
      createUser(
        email: $email,
        password: $password,
        name: $name
      ) {
        id
      }
    }
  `

  const variables = {
    email,
    password,
    name
  }

  return api.request<{ createUser: User }>(mutation, variables)
    .then(r => r.createUser.id)
}
