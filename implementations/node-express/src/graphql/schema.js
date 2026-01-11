/**
 * GraphQL Schema with vulnerabilities G01-G05
 *
 * VULNERABILITIES:
 * - G01: Introspection Exposed (enabled by default)
 * - G02: Nested Queries DoS (no depth limit)
 * - G03: Batching Attacks (arrays accepted)
 * - G04: Field Suggestions (hints in errors)
 * - G05: Authorization Bypass (no auth checks on sensitive resolvers)
 */

import {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLInt,
  GraphQLFloat,
  GraphQLBoolean,
  GraphQLList,
  GraphQLNonNull,
  GraphQLInputObjectType,
} from 'graphql';
import { db } from '../database.js';
import { hashPassword, verifyPassword, createToken } from '../middleware/auth.js';

// ==================== Types ====================

// User type - VULNERABILITY G05: Exposes sensitive fields
const UserType = new GraphQLObjectType({
  name: 'User',
  fields: () => ({
    id: { type: GraphQLInt },
    username: { type: GraphQLString },
    email: { type: GraphQLString },
    role: { type: GraphQLString },
    isActive: {
      type: GraphQLBoolean,
      resolve: (user) => Boolean(user.is_active)
    },
    createdAt: {
      type: GraphQLString,
      resolve: (user) => user.created_at
    },
    // VULNERABILITY G05: Exposing sensitive data without auth
    ssn: { type: GraphQLString },
    creditCard: {
      type: GraphQLString,
      resolve: (user) => user.credit_card
    },
    secretNote: {
      type: GraphQLString,
      resolve: (user) => user.secret_note
    },
    apiKey: {
      type: GraphQLString,
      resolve: (user) => user.api_key
    },
    // VULNERABILITY G02: Enables deep nesting
    orders: {
      type: new GraphQLList(OrderType),
      resolve: (user) => {
        return db.prepare('SELECT * FROM orders WHERE user_id = ?').all(user.id);
      }
    }
  })
});

// Product type - VULNERABILITY: Exposes internal data
const ProductType = new GraphQLObjectType({
  name: 'Product',
  fields: () => ({
    id: { type: GraphQLInt },
    name: { type: GraphQLString },
    description: { type: GraphQLString },
    price: { type: GraphQLFloat },
    stock: { type: GraphQLInt },
    category: { type: GraphQLString },
    isActive: {
      type: GraphQLBoolean,
      resolve: (product) => Boolean(product.is_active)
    },
    createdAt: {
      type: GraphQLString,
      resolve: (product) => product.created_at
    },
    // VULNERABILITY: Exposing internal data
    internalNotes: {
      type: GraphQLString,
      resolve: (product) => product.internal_notes
    },
    supplierCost: {
      type: GraphQLFloat,
      resolve: (product) => product.supplier_cost
    }
  })
});

// Order type - VULNERABILITY G02: Enables nesting back to User
const OrderType = new GraphQLObjectType({
  name: 'Order',
  fields: () => ({
    id: { type: GraphQLInt },
    status: { type: GraphQLString },
    totalAmount: {
      type: GraphQLFloat,
      resolve: (order) => order.total_amount
    },
    shippingAddress: {
      type: GraphQLString,
      resolve: (order) => order.shipping_address
    },
    notes: { type: GraphQLString },
    createdAt: {
      type: GraphQLString,
      resolve: (order) => order.created_at
    },
    // VULNERABILITY G02: Nesting back to User (circular)
    user: {
      type: UserType,
      resolve: (order) => {
        return db.prepare('SELECT * FROM users WHERE id = ?').get(order.user_id);
      }
    },
    items: {
      type: new GraphQLList(OrderItemType),
      resolve: (order) => {
        return db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
      }
    }
  })
});

// Order Item type
const OrderItemType = new GraphQLObjectType({
  name: 'OrderItem',
  fields: () => ({
    id: { type: GraphQLInt },
    quantity: { type: GraphQLInt },
    unitPrice: {
      type: GraphQLFloat,
      resolve: (item) => item.unit_price
    },
    product: {
      type: ProductType,
      resolve: (item) => {
        return db.prepare('SELECT * FROM products WHERE id = ?').get(item.product_id);
      }
    }
  })
});

// Challenge type
const ChallengeType = new GraphQLObjectType({
  name: 'Challenge',
  fields: {
    id: { type: GraphQLString },
    description: { type: GraphQLString },
    category: {
      type: GraphQLString,
      resolve: (flag) => flag.challenge_id.startsWith('G') ? 'graphql' : 'rest'
    }
  }
});

// Auth payload type
const AuthPayloadType = new GraphQLObjectType({
  name: 'AuthPayload',
  fields: {
    accessToken: { type: GraphQLString },
    tokenType: { type: GraphQLString },
    userId: { type: GraphQLInt },
    role: { type: GraphQLString }
  }
});

// ==================== Input Types ====================

const RegisterInput = new GraphQLInputObjectType({
  name: 'RegisterInput',
  fields: {
    username: { type: new GraphQLNonNull(GraphQLString) },
    email: { type: new GraphQLNonNull(GraphQLString) },
    password: { type: new GraphQLNonNull(GraphQLString) }
  }
});

const UpdateUserInput = new GraphQLInputObjectType({
  name: 'UpdateUserInput',
  fields: {
    username: { type: GraphQLString },
    email: { type: GraphQLString },
    password: { type: GraphQLString },
    role: { type: GraphQLString },  // VULNERABILITY: Can update role
    isActive: { type: GraphQLBoolean }
  }
});

const ProductInput = new GraphQLInputObjectType({
  name: 'ProductInput',
  fields: {
    name: { type: GraphQLString },
    description: { type: GraphQLString },
    price: { type: GraphQLFloat },
    stock: { type: GraphQLInt },
    category: { type: GraphQLString },
    internalNotes: { type: GraphQLString },
    supplierCost: { type: GraphQLFloat }
  }
});

// ==================== Queries ====================

const QueryType = new GraphQLObjectType({
  name: 'Query',
  fields: {
    // VULNERABILITY G05: No auth check - exposes all users with sensitive data
    users: {
      type: new GraphQLList(UserType),
      resolve: () => {
        return db.prepare('SELECT * FROM users').all();
      }
    },
    user: {
      type: UserType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) }
      },
      resolve: (_, { id }) => {
        return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      }
    },
    // Public product queries
    products: {
      type: new GraphQLList(ProductType),
      resolve: () => {
        return db.prepare('SELECT * FROM products').all();
      }
    },
    product: {
      type: ProductType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) }
      },
      resolve: (_, { id }) => {
        return db.prepare('SELECT * FROM products WHERE id = ?').get(id);
      }
    },
    // VULNERABILITY G05: Should require auth but doesn't check ownership
    orders: {
      type: new GraphQLList(OrderType),
      resolve: () => {
        return db.prepare('SELECT * FROM orders').all();
      }
    },
    order: {
      type: OrderType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) }
      },
      resolve: (_, { id }) => {
        return db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
      }
    },
    // Auth required (but context not checked)
    me: {
      type: UserType,
      resolve: (_, __, context) => {
        if (!context.user) return null;
        return context.user;
      }
    },
    challenges: {
      type: new GraphQLList(ChallengeType),
      resolve: () => {
        return db.prepare('SELECT challenge_id, description FROM flags').all()
          .map(f => ({ id: f.challenge_id, description: f.description }));
      }
    }
  }
});

// ==================== Mutations ====================

const MutationType = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    // Auth mutations
    register: {
      type: AuthPayloadType,
      args: {
        input: { type: new GraphQLNonNull(RegisterInput) }
      },
      resolve: (_, { input }) => {
        const { username, email, password } = input;

        const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
        if (existingUser) {
          throw new Error('Username or email already exists');
        }

        const passwordHash = hashPassword(password);
        const result = db.prepare(`
          INSERT INTO users (username, email, password_hash, role)
          VALUES (?, ?, ?, 'user')
        `).run(username, email, passwordHash);

        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

        return {
          accessToken: createToken(user),
          tokenType: 'bearer',
          userId: user.id,
          role: user.role
        };
      }
    },
    login: {
      type: AuthPayloadType,
      args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) }
      },
      resolve: (_, { username, password }) => {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

        if (!user) {
          throw new Error('User not found');
        }

        if (!verifyPassword(password, user.password_hash)) {
          throw new Error('Incorrect password');
        }

        return {
          accessToken: createToken(user),
          tokenType: 'bearer',
          userId: user.id,
          role: user.role
        };
      }
    },
    // VULNERABILITY G05: No ownership check
    updateUser: {
      type: UserType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) },
        input: { type: new GraphQLNonNull(UpdateUserInput) }
      },
      resolve: (_, { id, input }) => {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
        if (!user) {
          throw new Error('User not found');
        }

        const updates = [];
        const values = [];

        if (input.username !== undefined) { updates.push('username = ?'); values.push(input.username); }
        if (input.email !== undefined) { updates.push('email = ?'); values.push(input.email); }
        if (input.password !== undefined) { updates.push('password_hash = ?'); values.push(hashPassword(input.password)); }
        if (input.role !== undefined) { updates.push('role = ?'); values.push(input.role); }  // VULNERABILITY
        if (input.isActive !== undefined) { updates.push('is_active = ?'); values.push(input.isActive ? 1 : 0); }

        if (updates.length > 0) {
          values.push(id);
          db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
        }

        return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      }
    },
    deleteUser: {
      type: GraphQLBoolean,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) }
      },
      resolve: (_, { id }) => {
        const result = db.prepare('DELETE FROM users WHERE id = ?').run(id);
        return result.changes > 0;
      }
    },
    // Product mutations - VULNERABILITY G05: Should be admin only
    createProduct: {
      type: ProductType,
      args: {
        input: { type: new GraphQLNonNull(ProductInput) }
      },
      resolve: (_, { input }) => {
        const result = db.prepare(`
          INSERT INTO products (name, description, price, stock, category, internal_notes, supplier_cost)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          input.name,
          input.description || null,
          input.price || 0,
          input.stock || 0,
          input.category || null,
          input.internalNotes || null,
          input.supplierCost || null
        );

        return db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
      }
    },
    updateProduct: {
      type: ProductType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) },
        input: { type: new GraphQLNonNull(ProductInput) }
      },
      resolve: (_, { id, input }) => {
        const product = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
        if (!product) {
          throw new Error('Product not found');
        }

        const updates = [];
        const values = [];

        if (input.name !== undefined) { updates.push('name = ?'); values.push(input.name); }
        if (input.description !== undefined) { updates.push('description = ?'); values.push(input.description); }
        if (input.price !== undefined) { updates.push('price = ?'); values.push(input.price); }
        if (input.stock !== undefined) { updates.push('stock = ?'); values.push(input.stock); }
        if (input.category !== undefined) { updates.push('category = ?'); values.push(input.category); }
        if (input.internalNotes !== undefined) { updates.push('internal_notes = ?'); values.push(input.internalNotes); }
        if (input.supplierCost !== undefined) { updates.push('supplier_cost = ?'); values.push(input.supplierCost); }

        if (updates.length > 0) {
          values.push(id);
          db.prepare(`UPDATE products SET ${updates.join(', ')} WHERE id = ?`).run(...values);
        }

        return db.prepare('SELECT * FROM products WHERE id = ?').get(id);
      }
    },
    deleteProduct: {
      type: GraphQLBoolean,
      args: {
        id: { type: new GraphQLNonNull(GraphQLInt) }
      },
      resolve: (_, { id }) => {
        const result = db.prepare('DELETE FROM products WHERE id = ?').run(id);
        return result.changes > 0;
      }
    }
  }
});

// ==================== Schema ====================

const schema = new GraphQLSchema({
  query: QueryType,
  mutation: MutationType
});

export default schema;
