import path from 'node:path'
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

export default {
  entry: './src/test-chutney.ts',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    fallback: {
      // node builtins
      "util": require.resolve("util/"),
      "url": require.resolve("url/"),
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/"),
      "http": require.resolve("stream-http"),
      "https": require.resolve("https-browserify"),
      "querystring": require.resolve("querystring-es3"),
      "assert": require.resolve("assert/"),
      "crypto": require.resolve("crypto-browserify"),
      "events": require.resolve("events/"),
      "net": require.resolve("net-browserify"),
      "tls": require.resolve("tls-browserify"),
    }
  },
  externals: {
    "node:util": require.resolve("util/"),
    "node:url": require.resolve("url/"),
    "node:stream": require.resolve("stream-browserify"),
    "node:buffer": require.resolve("buffer/"),
    "node:http": require.resolve("stream-http"),
    "node:https": require.resolve("https-browserify"),
    "node:querystring": require.resolve("querystring-es3"),
    "node:fs": false,
    "node:assert": require.resolve("assert/"),
    "node:crypto": require.resolve("crypto-browserify"),
    "node:events": require.resolve("events/"),
    "node:net": require.resolve("net-browserify"),
    "node:tls": require.resolve("tls-browserify"),
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
};
