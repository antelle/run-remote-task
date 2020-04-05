#!/usr/bin/env node

const fs = require('fs');
const minimist = require('minimist');
const { runRemoteTask, startServer } = require('./');

const args = minimist(process.argv.slice(2));

if (!args.config || (!args.server && !args.client) || args.help) {
    console.log(
        'Usage: \n' +
            '   As server: run-remote-task --config=path/to/config.json --server\n' +
            '   As client: run-remote-task --config=path/to/config.json --client --input=input-file'
    );
    process.exit(1);
}

run();

async function run() {
    const config = JSON.parse(fs.readFileSync(args.config));
    if (args.server) {
        startServer(config);
    } else {
        if (!args.input) {
            console.error('Input file must be specified as --input=input-file');
            process.exit(1);
        }
        try {
            await runRemoteTask(config, fs.readFileSync(args.input));
        } catch (e) {
            console.error('Received an error:', e);
            process.exit(2);
        }
    }
}
