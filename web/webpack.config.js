const path = require('path')
const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const CopyPlugin = require('copy-webpack-plugin')
const NodePolyfillPlugin = require("node-polyfill-webpack-plugin")

const DIST = path.resolve(__dirname, 'dist')

module.exports = {
    mode: 'development',
    entry: './src/index.js',
    output: {
        filename: 'bundle.js',
        libraryTarget: 'umd',
        library:'umd',
        path: DIST,
        publicPath: DIST,
    },
    devServer: {
        contentBase: DIST,
        port: 9011,
        writeToDisk: true,
        hot: true,
    },
    module: {
        rules: [
            {
                test: /\.css$/i,
                use: ["style-loader", "css-loader"],
            },
        ],
    },
    plugins: [
	new NodePolyfillPlugin(),
        new CleanWebpackPlugin({ cleanStaleWebpackAssets: false }),
        // for build scripts
        new CopyPlugin({
            patterns: [
                {
                    flatten: true,
                    from: './src/*',
                    globOptions: {
                        ignore: ['**/*.js'],
                    },
                }
            ],
        }),
    ],
    resolve: {
	fallback: {
	    net: false,
            tls: false
        },
    }
}
