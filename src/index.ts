export interface Env {
    services: D1Database;
}
const JWT_SECRET = "IhEjJzMoPp3sUvXy2Aq6t9wBcE5gF8rU"
export default {
    async fetch(request: Request, env: Env) {
        try {
            return new Response(await handleRequest(request, env));
        } catch (err) {
            return new Response(err?.toString() || 'no error!');
        }
    }
};

async function handleRequest(request, env) {
    const {pathname} = new URL(request.url);
    const authController = new AuthController(env);

    if (request.method === "POST" && pathname === "/api/register") {
        return await authController.register(request);
    }

    if (request.method === "POST" && pathname === "/api/login") {
        return await authController.login(request);
    }

    if (request.method === "PUT" && pathname === "/api/user") {
        return await authController.edit(request);
    }

    if (request.method === "POST" && pathname === "/api/active") {
        return await authController.activeCode(request);
    }

    if (request.method === "POST" && pathname === "/api/activate") {
        return await authController.activateUser(request);
    }

    if (request.method === "GET" && pathname === "/api/user") {
        return await authController.getUserInfo(request);
    }

    // Return a 404 response for any other request
    return new Response("Not found", {status: 404});
}

interface User {
    id: number;
    username: string;
    password: string;
    email: string;
    mobile: string;
    fname: string;
    lname: string;
    active: boolean;
    activation_code: string;
    created_at: string;
    updated_at: string;
}
interface ValidatorOptions {
    required?: boolean;
    pattern?: string | RegExp;
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    validate?: (value: any) => boolean;
    message?: string;
}

export class AuthController {

    private jwt: Jwt;

    constructor(env) {
        this.orm = env.services;
        this.jwt = new Jwt(JWT_SECRET);
    }

    async register(request: Request): Promise<Response> {
        try {
            const body = await request.json();
            const validationErrors = await this.validate(body);
            if (validationErrors.length > 0) {
                return jsonResponse({
                    success: false,
                    message: 'Validation Error',
                    errors: validationErrors,
                }, 400);
            }

            const existingUser = await this.db.get<User>(`users_${body.username}`);
            if (existingUser) {
                return jsonResponse({
                    success: false,
                    message: 'Username is already taken',
                    errors: [],
                }, 400);
            }

            const hashedPassword = await bcrypt.hash(body.password, 10);
            const user: User = {
                id: Date.now(),
                username: body.username,
                password: hashedPassword,
                email: body.email,
                mobile: body.mobile,
                fname: body.fname,
                lname: body.lname,
                active: false,
                activation_code: Math.random().toString(36).slice(2),
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
            };
            await this.db.put(`users_${user.username}`, user);

            return jsonResponse({
                success: true,
                message: 'User registered successfully',
                data: user,
            }, 201);
        } catch (err) {
            console.error('Error while registering user: ', err);
            return jsonResponse({
                success: false,
                message: 'Internal Server Error',
                errors: [],
            }, 500);
        }
    }

    async validate<T>(input: T, validatorOptions?: ValidatorOptions): Promise<string[]> {
        const errors = await validate(input, validatorOptions);
        const errorMessages: string[] = [];
        if (errors.length > 0) {
            errors.forEach((err) => {
                Object.values(err.constraints).forEach((msg) => {
                    errorMessages.push(msg);
                });
            });
        }
        return errorMessages;
    }

    async login(request: Request): Promise<Response> {
        const body = await request.json();
        const validationResult = this.validate(body, ['email', 'mobile', 'password']);
        if (validationResult.errors.length) {
            return jsonResponse({
                errors: validationResult.errors
            });
        }

        const { email, mobile, password } = validationResult.values;

        const user = await this.orm.findOne(User, {
            email: email ?? undefined,
            mobile: mobile ?? undefined
        });

        if (!user || !await user.comparePassword(password)) {
            return jsonResponse({
                errors: [{ message: 'Invalid email or password' }]
            });
        }

        const token = JWT.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });

        return jsonResponse({
            data: { token }
        });
    }

    async edit(request: Request): Promise<Response> {
        try {
            const body = await request.json();
            const { id } = request.params;

            const user = await this.orm.get<User>(User, Number(id));

            if (!user) {
                return this.jsonResponse(
                    { message: "User not found" },
                    StatusCode.NotFound
                );
            }

            const updatedUser = Object.assign(user, body);
            await this.orm.save<User>(User, updatedUser);

            return this.jsonResponse(updatedUser);
        } catch (e) {
            return this.jsonResponse(
                { message: "Failed to edit user", error: e.message },
                StatusCode.BadRequest
            );
        }
    }

    async activateUser(userId, code) {
        try {
            const user = await this.orm.findOne({id: userId});
            if (!user) {
                throw new Error('User not found');
            }
            if (user.active) {
                throw new Error('User already activated');
            }
            if (user.activation_code !== code) {
                throw new Error('Activation code incorrect');
            }
            await this.orm.update({id: userId}, {active: true, activation_code: null});
            return {message: 'User activated successfully'};
        } catch (error) {
            console.error(`Error activating user: ${error.message}`);
            return {error: error.message};
        }
    }

    async getUserInfo(userId) {
        try {
            const user = await this.orm.findOne({id: userId});
            if (!user) {
                throw new Error('User not found');
            }
            const {password, ...userInfo} = user;
            return {user: userInfo};
        } catch (error) {
            console.error(`Error getting user info: ${error.message}`);
            return {error: error.message};
        }
    }

}


class ORM {
    constructor(db) {
        this.db = db;
    }

    async find(tableName, conditions = {}, fields = [], options = {}) {
        const {where = "", params = []} = this._getWhereClause(conditions);
        const {select = "", orderBy = "", limit = ""} = options;

        const selectClause = fields.length > 0 ? fields.join(", ") : "*";
        const query = `SELECT ${selectClause} FROM ${tableName} ${where} ${select} ${orderBy} ${limit}`;
        const result = await this.db.prepare(query).bind(params).all();
        return result;
    }

    async findOne(tableName, conditions = {}, fields = []) {
        const {where = "", params = []} = this._getWhereClause(conditions);

        const selectClause = fields.length > 0 ? fields.join(", ") : "*";
        const query = `SELECT ${selectClause} FROM ${tableName} ${where} LIMIT 1`;
        const result = await this.db.prepare(query).bind(params).get();
        return result;
    }

    async count(tableName, conditions = {}) {
        const {where = "", params = []} = this._getWhereClause(conditions);

        const query = `SELECT COUNT(*) as count FROM ${tableName} ${where}`;
        const result = await this.db.prepare(query).bind(params).get();
        return result.count;
    }

    async insert(tableName, data = {}) {
        const {fields, values, placeholders} = this._getInsertClause(data);
        const query = `INSERT INTO ${tableName} (${fields}) VALUES (${placeholders})`;
        const result = await this.db.prepare(query).bind(values).run();
        return result.lastInsertRowid;
    }

    async update(tableName, conditions = {}, data = {}) {
        const {fields, params} = this._getUpdateClause(data);
        const {where, whereParams} = this._getWhereClause(conditions);

        const query = `UPDATE ${tableName} SET ${fields} ${where}`;
        const result = await this.db.prepare(query).bind([...params, ...whereParams]).run();
        return result.changes;
    }

    async upsert(tableName, conditions = {}, data = {}) {
        const existingRow = await this.findOne(tableName, conditions);
        if (existingRow) {
            return await this.update(tableName, conditions, data);
        } else {
            const mergedData = {...conditions, ...data};
            return await this.insert(tableName, mergedData);
        }
    }

    async delete(tableName, conditions = {}) {
        const {where, params} = this._getWhereClause(conditions);

        const query = `DELETE FROM ${tableName} ${where}`;
        const result = await this.db.prepare(query).bind(params).run();
        return result.changes;
    }

    _getInsertClause(data) {
        const fields = Object.keys(data).join(", ");
        const values = Object.values(data);
        const placeholders = values.map(() => "?").join(", ");
        return {fields, values, placeholders};
    }

    _getUpdateClause(data) {
        const fields = Object.keys(data).map((key) => `${key} = ?`).join(", ");
        const params = Object.values(data);
        return {fields, params};
    }

    _getWhereClause(conditions) {
        const where = Object.keys(conditions)
            .map((key) => `${key} = ?`)
            .join(" AND ");
        const params = Object.values(conditions);
        return {where: where ? `WHERE ${where}` : "", params};
    }
}


class JsonResponse {
    constructor(statusCode, message, data = null) {
        this.statusCode = statusCode;
        this.message = message;
        this.data = data;
    }

    toJson() {
        return JSON.stringify({
            status: this.statusCode,
            message: this.message,
            data: this.data,
        });
    }

    toResponse() {
        return new Response(this.toJson(), {
            headers: { "Content-Type": "application/json" },
        });
    }
}

class Jwt {
    constructor(secret) {
        this.secret = secret;
    }

    sign(payload) {
        const jwtHeader = { alg: "HS256", typ: "JWT" };
        const encodedHeader = btoa(JSON.stringify(jwtHeader)).replace(/=/g, "");
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, "");

        const signature = btoa(
            CryptoJS.HmacSHA256(`${encodedHeader}.${encodedPayload}`, this.secret)
                .toString(CryptoJS.enc.Base64)
                .replace(/=/g, "")
        );

        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }

    verify(token) {
        const [encodedHeader, encodedPayload, signature] = token.split(".");
        const jwtHeader = JSON.parse(atob(encodedHeader + "=="));
        const payload = JSON.parse(atob(encodedPayload + "=="));

        const expectedSignature = CryptoJS.HmacSHA256(
            `${encodedHeader}.${encodedPayload}`,
            this.secret
        )
            .toString(CryptoJS.enc.Base64)
            .replace(/=/g, "");

        if (signature !== expectedSignature) {
            throw new Error("Invalid token signature");
        }

        return payload;
    }
}
