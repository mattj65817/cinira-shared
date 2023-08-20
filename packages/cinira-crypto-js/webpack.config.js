const path = require("path"),
    ZipPlugin = require("zip-webpack-plugin");

module.exports = {
    experiments: {
        outputModule: true
    },
    module: {
        rules: [{
            exclude: "/node_modules",
            test: /\.ts$/,
            use: "ts-loader"
        }]
    },
    output: {
        filename: "index.mjs",
        library: {
            type: "module"
        },
        path: path.resolve(__dirname, "build/out")
    },
    plugins: [
        new ZipPlugin({
            path: "../dist",
            filename: "module.zip"
        })
    ],
    resolve: {
        extensions: [".js", ".ts"],
        fallback: {
            crypto: false
        }
    }
};
