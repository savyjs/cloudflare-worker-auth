addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const controller = new AuthController();
  await controller.init();

  // Handle requests and call the appropriate controller methods
}

class AuthController {
  constructor() {
   this.orm = new DurableORM('USERS', 'users.db');
  }

  async register(data) {
    try {
      const errors = this.validate(data);
      if (Object.keys(errors).length) {
        throw new ValidationError('Validation failed', errors);
      }
      
      data.password = await hashPassword(data.password);
      data.active = false;
      data.created_at = Date.now();
      
      const result = await this.orm.insert(data);
      return { id: result.id };
    } catch (error) {
      if (error instanceof ValidationError) {
        return { errors: error.errors };
      }
      console.error(`Error registering user: ${error.message}`);
      return { error: 'Internal server error' };
    }
  }

  async login(username, password) {
    try {
      const user = await this.orm.findOne({ email: username }) || await this.orm.findOne({ mobile: username });
      if (!user) {
        throw new Error('User not found');
      }
      const passwordMatches = await verifyPassword(password, user.password);
      if (!passwordMatches) {
        throw new Error('Password incorrect');
      }
      if (!user.active) {
        throw new Error('Account not activated');
      }
      const token = generateToken(user);
      return { token };
    } catch (error) {
      console.error(`Error logging in user: ${error.message}`);
      return { error: error.message };
    }
  }

  async editUser(userId, data) {
    try {
      const user = await this.orm.findOne({ id: userId });
      if (!user) {
        throw new Error('User not found');
      }
      const newData = { ...user, ...data };
      await this.orm.update({ id: userId }, newData);
      return { message: 'User updated successfully' };
    } catch (error) {
      console.error(`Error editing user: ${error.message}`);
      return { error: error.message };
    }
  }

  async activateUser(userId, code) {
    try {
      const user = await this.orm.findOne({ id: userId });
      if (!user) {
        throw new Error('User not found');
      }
      if (user.active) {
        throw new Error('User already activated');
      }
      if (user.activation_code !== code) {
        throw new Error('Activation code incorrect');
      }
      await this.orm.update({ id: userId }, { active: true, activation_code: null });
      return { message: 'User activated successfully' };
    } catch (error) {
      console.error(`Error activating user: ${error.message}`);
      return { error: error.message };
    }
  }

  async getUserInfo(userId) {
    try {
      const user = await this.orm.findOne({ id: userId });
      if (!user) {
        throw new Error('User not found');
      }
      const { password, ...userInfo } = user;
      return { user: userInfo };
    } catch (error) {
      console.error(`Error getting user info: ${error.message}`);
      return { error: error.message };
    }
  }

  validate(data) {
  const errors = {};
  const emailRegex = /^\S+@\S+\.\S+$/;
  const mobileRegex = /^(\+98|0)?9\d{9}$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$/;

  if (!data.mobile || !mobileRegex.test(data.mobile)) {
    errors.mobile = {
      en: 'Mobile number is required and should be in a valid format',
      fa: 'شماره موبایل الزامیست و باید به فرمت معتبر باشد'
    };
  }
  if (!data.password || !passwordRegex.test(data.password)) {
    errors.password = {
      en: 'Password should be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, and one number',
      fa: 'رمز عبور باید حداقل ۶ کاراکتر باشد و شامل حداقل یک حرف بزرگ، یک حرف کوچک و یک عدد باشد'
    };
  }
  if (data.email && !emailRegex.test(data.email)) {
    errors.email = {
      en: 'Email should be in a valid format',
      fa: 'ایمیل باید به فرمت معتبر باشد'
    };
  }

  return errors;
}


}



class DurableORM {
  constructor(kvNamespace, durableObjectName) {
    this.db = new Database(kvNamespace, durableObjectName);
  }

  async where(tableName, conditions) {
    let query = `SELECT * FROM ${tableName}`;
    const values = [];
    if (conditions && Object.keys(conditions).length > 0) {
      query += ' WHERE';
      let first = true;
      for (const field in conditions) {
        if (first) {
          first = false;
        } else {
          query += ' AND';
        }
        if (Array.isArray(conditions[field])) {
          query += ` ${field} IN (${Array(conditions[field].length).fill('?').join(',')})`;
          values.push(...conditions[field]);
        } else {
          query += ` ${field} = ?`;
          values.push(conditions[field]);
        }
      }
    }
    const rows = await this.db.query(query, values);
    return rows;
  }

  async insert(tableName, data) {
    const fields = Object.keys(data).join(',');
    const placeholders = Array(Object.keys(data).length).fill('?').join(',');
    const values = Object.values(data);
    const query = `INSERT INTO ${tableName} (${fields}) VALUES (${placeholders})`;
    const result = await this.db.query(query, values);
    return result.lastID;
  }

  async update(tableName, conditions, data) {
    let query = `UPDATE ${tableName} SET`;
    const values = [];
    const updateFields = Object.keys(data);
    for (let i = 0; i < updateFields.length; i++) {
      const field = updateFields[i];
      query += ` ${field} = ?`;
      values.push(data[field]);
      if (i < updateFields.length - 1) {
        query += ',';
      }
    }
    query += ' WHERE';
    let first = true;
    for (const field in conditions) {
      if (first) {
        first = false;
      } else {
        query += ' AND';
      }
      query += ` ${field} = ?`;
      values.push(conditions[field]);
    }
    const result = await this.db.query(query, values);
    return result.changes;
  }

  async upsert(tableName, conditions, data) {
    const rows = await this.where(tableName, conditions);
    if (rows.length > 0) {
      return this.update(tableName, conditions, data);
    } else {
      const insertData = Object.assign({}, conditions, data);
      return this.insert(tableName, insertData);
    }
  }

  async find(tableName, id) {
    const rows = await this.where(tableName, { id });
    if (rows.length > 0) {
      return rows[0];
    } else {
      return null;
    }
  }

  async findOne(tableName, conditions) {
    const rows = await this.where(tableName, conditions);
    if (rows.length > 0) {
      return rows[0];
    } else {
      return null;
    }
  }

  async delete(tableName, conditions) {
    let query = `DELETE FROM ${tableName} WHERE`;
    const values = [];
    let first = true;
    for (const field in conditions) {
      if (first) {
        first = false;
      } else {
        query += ' AND';
      }
      query += ` ${field} = ?`;
      values.push(conditions[field]);
    }
    const result = await this.db.query(query, values);
    return result.changes;
  }


  async count(filter) {
    const results = await this.where(filter);
    return results.length;
  }

  _buildKey(data) {
    const keys = Object.keys(data).sort();
    const values = keys.map((k) => data[k]);
    return JSON.stringify(keys.concat(values));
  }
}