const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const AWS = require('aws-sdk');
const { Storage } = require('@google-cloud/storage');
const { execSync } = require('child_process');

function configureHost(config) {
    if (!config.server && !config.aws && !config.gcp) {
        throw new Error(
            'Server is missing in config, there should be either of: "server", "aws", "gcp'
        );
    }
    if (config.aws) {
        AWS.config.update(config.aws);
    }
}

async function runRemoteTask(config, inputData) {
    for (const prop of ['clientPrivateKey', 'clientPublicKey', 'serverPublicKey', 'pollMillis']) {
        if (!config[prop]) {
            throw new Error(`config.${prop} is empty`);
        }
    }
    configureHost(config);

    if (!runRemoteTask.initialized) {
        const clientPrivateKey = fs.readFileSync(config.clientPrivateKey);
        const clientPublicKey = fs.readFileSync(config.clientPublicKey);
        const serverPublicKey = fs.readFileSync(config.serverPublicKey);

        testSign(clientPrivateKey, clientPublicKey, serverPublicKey);

        runRemoteTask.clientPrivateKey = clientPrivateKey;
        runRemoteTask.clientPublicKey = clientPublicKey;
        runRemoteTask.serverPublicKey = serverPublicKey;

        runRemoteTask.initialized = true;
    }

    const inputSignature = sign(inputData, runRemoteTask.clientPrivateKey);
    const taskId = crypto.randomBytes(16).toString('hex');

    console.log(`Sending a remote task with ID ${taskId}...`);

    const dt = new Date();

    await upload(config, getTaskFileUrl(dt, taskId, 'in', 'dat'), inputData);
    await upload(config, getTaskFileUrl(dt, taskId, 'in', 'sig'), inputSignature);

    console.log(`Task ${taskId} successfully sent, waiting for results...`);

    let task;

    while (true) {
        if (new Date() - dt > config.taskExpirationMillis) {
            throw new Error('Timed out');
        }
        await timeout(config.pollMillis);
        try {
            task = toTasks(await listFiles(config)).filter(
                (task) => task.id === taskId && task.out && task.out.sig
            )[0];
            console.log(`Poll: ${task ? 'result found' : 'no results yet'}`);
            if (task) {
                break;
            }
        } catch (e) {
            console.error('Poll error', e);
        }
    }

    const sigFile = await downloadFile(config, task.out.sig.url);
    const signature = fs.readFileSync(sigFile);
    fs.unlinkSync(sigFile);

    try {
        if (task.out.dat) {
            const outFile = await downloadFile(config, task.out.dat.url);
            const outData = fs.readFileSync(outFile);
            if (!verify(outData, signature, runRemoteTask.serverPublicKey)) {
                throw new Error('Received a result with a bad signature');
            }
            console.log(`Task ${taskId} completed successfully, result: ${outFile}`);
            return { file: outFile, data: outData };
        } else if (task.out.err) {
            const errFile = task.out.err ? await downloadFile(config, task.out.err.url) : null;
            const errData = fs.readFileSync(errFile);
            fs.unlinkSync(errFile);
            if (!verify(errData, signature, runRemoteTask.serverPublicKey)) {
                throw new Error('Received an error with a bad signature');
            }
            const err = errData.toString('utf8');
            console.log(`Task ${taskId} completed with error:\n${err}`);
            throw new Error(err);
        } else {
            throw new Error('No output or error file found');
        }
    } finally {
        for (const inout of ['in', 'out']) {
            if (task[inout]) {
                for (const file of Object.values(task[inout])) {
                    console.log(`Deleting task file ${file.url}`);
                    await deleteFile(config, file.url);
                }
            }
        }
    }
}

async function startServer(config) {
    for (const prop of ['serverPrivateKey', 'serverPublicKey', 'clientPublicKey', 'pollMillis']) {
        if (!config[prop]) {
            throw new Error(`config.${prop} is empty`);
        }
    }
    configureHost(config);

    const serverPrivateKey = fs.readFileSync(config.serverPrivateKey);
    const serverPublicKey = fs.readFileSync(config.serverPublicKey);
    const clientPublicKey = fs.readFileSync(config.clientPublicKey);
    testSign(serverPrivateKey, serverPublicKey, clientPublicKey);

    const desc =
        config.server ||
        (config.gcp && `GCP:${config.gcp.projectId}/${config.gcp.bucketName}`) ||
        (config.aws && `AWS:${config.aws.bucket}`) ||
        '?';
    console.log(`Starting server at ${desc}...`);

    while (true) {
        try {
            const tasks = toTasks(await listFiles(config)).filter((task) => !task.out);
            console.log(`Poll: ${tasks.length} tasks pending`);
            const task = tasks[0];
            if (task) {
                await runTask(config, task, clientPublicKey, serverPrivateKey);
            }
            await timeout(config.pollMillis);
        } catch (e) {
            console.error('Poll error', e);
            await timeout(config.pollMillis);
        }
    }
}

async function runTask(config, task, clientPublicKey, serverPrivateKey) {
    console.log(`Downloading task ${task.id}, ${task.date.toISOString()}`);

    const inFile = await downloadFile(config, task.in.dat.url);
    const sigFile = await downloadFile(config, task.in.sig.url);

    const signature = fs.readFileSync(sigFile);
    fs.unlinkSync(sigFile);

    const isValid = verify(fs.readFileSync(inFile), signature, clientPublicKey);
    if (isValid) {
        console.log(`Running task ${task.id}, ${task.date.toISOString()}`);
        const outFile = inFile.replace('.in.dat', '.out.dat');
        try {
            execSync(config.command, {
                env: {
                    INPUT: inFile,
                    OUTPUT: outFile
                }
            });
            if (!fs.existsSync(outFile)) {
                console.log(
                    `No output file created for task ${task.id}, ${task.date.toISOString()}`
                );
                throw new Error('Output file was not created');
            }
            fs.unlinkSync(inFile);
            await uploadTaskResult(config, task, outFile, null, serverPrivateKey);
            fs.unlinkSync(outFile);
        } catch (e) {
            if (!runTask.retries) {
                runTask.retries = {};
            }
            const retryCount = runTask.retries[task.id] || 0;
            runTask.retries[task.id] = retryCount + 1;
            console.error(
                `Task failed: ${task.id}, ${task.date.toISOString()}, ` +
                    `retry ${retryCount} / ${config.commandRetries}`
            );
            if (retryCount >= config.commandRetries) {
                delete runTask.retries[task.id];
                fs.unlinkSync(inFile);
                await uploadTaskResult(config, task, null, e.toString(), serverPrivateKey);
            }
        }
    } else {
        console.error(`Bad signature for task ${task.id}, ${task.date.toISOString()}`);
        fs.unlinkSync(inFile);
        await uploadTaskResult(config, task, null, 'Bad signature', serverPrivateKey);
    }
}

async function uploadTaskResult(config, task, outFile, error, serverPrivateKey) {
    const resStr = outFile ? 'OK' : 'Error';
    console.error(`Uploading result for task ${task.id}, ${task.date.toISOString()}: ${resStr}`);

    const data = outFile ? fs.readFileSync(outFile) : Buffer.from(error.toString());
    const dataExt = outFile ? 'dat' : 'err';
    const signature = sign(data, serverPrivateKey);

    await upload(config, getTaskFileUrl(task.date, task.id, 'out', dataExt), data);
    await upload(config, getTaskFileUrl(task.date, task.id, 'out', 'sig'), signature);

    console.error(`Upload complete for task ${task.id}, ${task.date.toISOString()}`);
}

function toTasks(files) {
    const tasks = {};
    for (const file of files) {
        if (!tasks[file.taskId]) {
            tasks[file.taskId] = {};
        }
        if (!tasks[file.taskId][file.inout]) {
            tasks[file.taskId][file.inout] = {};
        }
        tasks[file.taskId][file.inout][file.ext] = file;
    }
    const list = Object.values(tasks);
    return list
        .filter((task) => task.in && task.in.sig && task.in.dat)
        .map((task) => ({ ...task, date: task.in.sig.date, id: task.in.sig.taskId }))
        .sort((x, y) => x.date - y.date);
}

async function deleteExpiredFiles(config, files) {
    const res = [];
    const expirationDate = Date.now() - config.taskExpirationMillis * 2;
    for (const file of files) {
        if (file.date < expirationDate) {
            console.log(`Deleting expired file ${file.url}`);
            try {
                await deleteFile(config, file.url);
            } catch (e) {
                console.error('Error deleting expired file', e);
            }
        } else {
            res.push(file);
        }
    }
    return res;
}

function testSign(privateKey, publicKey, otherPublicKey) {
    const data = Buffer.from('test');
    const signature = sign(data, privateKey);
    if (!verify(data, signature, publicKey)) {
        throw new Error(
            'Could not verify data signed by private key, make sure keypair is correct'
        );
    }
    if (verify(data, signature, otherPublicKey)) {
        throw new Error('Looks like client and server keys are the same');
    }
}

function sign(data, privateKey) {
    const signer = crypto.createSign('sha512');
    signer.update(data);
    return signer.sign(privateKey);
}

function verify(data, signature, publicKey) {
    const verifier = crypto.createVerify('sha512');
    verifier.update(data);
    return verifier.verify(publicKey, signature);
}

function upload(config, fileUrl, data) {
    return new Promise((resolve, reject) => {
        if (config.gcp) {
            const ws = new Storage(config.gcp)
                .bucket(config.gcp.bucketName)
                .file(fileUrl)
                .createWriteStream();
            ws.on('error', (err) => {
                console.error('Upload error', err);
                reject(err);
            });
            ws.on('finish', () => {
                resolve();
            });
            ws.end(data);
        } else if (config.aws) {
            const params = {
                Bucket: config.aws.bucket,
                StorageClass: 'REDUCED_REDUNDANCY',
                Key: fileUrl,
                Body: data
            };
            return new AWS.S3().upload(params, async (err) => {
                if (err) {
                    console.error('Upload error', err);
                    return reject(err);
                }
                resolve();
            });
        } else {
            const req = proto(config).request(
                config.server + fileUrl,
                {
                    method: 'PUT',
                    headers: getAuthHeader(config)
                },
                (res) => {
                    if (res.statusCode !== 201) {
                        console.error(`Upload error: HTTP status code ${res.statusCode}`);
                        return reject(`HTTP status code ${res.statusCode}`);
                    }
                    resolve();
                }
            );
            req.on('error', (e) => {
                console.error('HTTP request error', e);
                reject('HTTP request error: ' + e);
            });
            req.write(data);
            req.end();
        }
    });
}

function listFiles(config) {
    return new Promise((resolve, reject) => {
        if (config.gcp) {
            new Storage(config.gcp).bucket(config.gcp.bucketName).getFiles(async (err, files) => {
                if (err) {
                    console.error('List error', err);
                    return reject(err);
                }
                const urls = files.map((item) => item.name);
                resolve(await deleteExpiredFiles(config, convertUrls(urls)));
            });
        } else if (config.aws) {
            return new AWS.S3().listObjects({ Bucket: config.aws.bucket }, async (err, data) => {
                if (err) {
                    console.error('List error', err);
                    return reject(err);
                }
                const urls = data.Contents.map((item) => item.Key);
                resolve(await deleteExpiredFiles(config, convertUrls(urls)));
            });
        } else {
            const req = proto(config).get(
                config.server,
                { headers: getAuthHeader(config) },
                (res) => {
                    if (res.statusCode !== 200) {
                        console.error(`Poll error: HTTP status code ${res.statusCode}`);
                        return reject(`HTTP status code ${res.statusCode}`);
                    }
                    const body = [];
                    res.on('data', (chunk) => body.push(chunk));
                    res.on('end', async () => {
                        const resStr = Buffer.concat(body).toString('utf8');
                        const urls = [...resStr.matchAll(/href="([\w\.\-%]+)"/gi)].map((match) =>
                            decodeURIComponent(match[1])
                        );
                        resolve(await deleteExpiredFiles(config, convertUrls(urls)));
                    });
                }
            );
            req.on('error', (e) => {
                console.error('HTTP request error', e);
                reject('HTTP request error: ' + e);
            });
        }
    });

    function convertUrls(urls) {
        return urls
            .map((url) => {
                const match = url.match(/^(\d+)-(\w+)\.(in|out)\.(dat|sig|err)$/);
                if (!match) {
                    return undefined;
                }
                const [, date, taskId, inout, ext] = match;
                return { date: new Date(+date), taskId, inout, ext, url };
            })
            .filter((task) => task);
    }
}

function downloadFile(config, fileUrl) {
    return new Promise((resolve, reject) => {
        if (config.gcp) {
            const destination = path.join(os.tmpdir(), path.basename(fileUrl));
            new Storage(config.gcp)
                .bucket(config.gcp.bucketName)
                .file(fileUrl)
                .download({ destination }, async (err) => {
                    if (err) {
                        console.error('Download error', err);
                        reject(err);
                    }
                    resolve(destination);
                });
        } else if (config.aws) {
            const params = { Bucket: config.aws.bucket, Key: fileUrl };
            return new AWS.S3().getObject(params, async (err, data) => {
                if (err) {
                    console.error('Download error', err);
                    reject(err);
                }
                const fileName = path.join(os.tmpdir(), path.basename(fileUrl));
                fs.writeFileSync(fileName, data.Body);
                resolve(fileName);
            });
        } else {
            const req = proto(config).get(
                config.server + fileUrl,
                { headers: getAuthHeader(config) },
                (res) => {
                    if (res.statusCode !== 200) {
                        console.error(`Download error: HTTP status code ${res.statusCode}`);
                        return reject(`HTTP status code ${res.statusCode}`);
                    }

                    const fileName = path.join(os.tmpdir(), path.basename(fileUrl));
                    const file = fs.createWriteStream(fileName);

                    res.pipe(file);

                    file.on('finish', () => {
                        file.close(() => resolve(fileName));
                    });
                }
            );
            req.on('error', (e) => {
                console.error('HTTP request error', e);
                reject('HTTP request error: ' + e);
            });
            req.end();
        }
    });
}

function deleteFile(config, fileUrl) {
    return new Promise((resolve, reject) => {
        if (config.gcp) {
            new Storage(config.gcp)
                .bucket(config.gcp.bucketName)
                .file(fileUrl)
                .delete(async (err) => {
                    if (err) {
                        console.error('Delete error', err);
                        return reject(err);
                    }
                    resolve();
                });
        } else if (config.aws) {
            const params = { Bucket: config.aws.bucket, Key: fileUrl };
            return new AWS.S3().deleteObject(params, async (err) => {
                if (err) {
                    console.error('Delete error', err);
                    return reject(err);
                }
                resolve();
            });
        } else {
            const req = proto(config).request(
                config.server + fileUrl,
                { method: 'DELETE', headers: getAuthHeader(config) },
                (res) => {
                    if (res.statusCode !== 204) {
                        console.error(`Delete error: HTTP status code ${res.statusCode}`);
                        return reject(`HTTP status code ${res.statusCode}`);
                    }
                    resolve();
                }
            );
            req.on('error', (e) => {
                console.error('HTTP request error', e);
                reject('HTTP request error: ' + e);
            });
            req.end();
        }
    });
}

function proto(config) {
    return require(config.server.startsWith('https') ? 'https' : 'http');
}

function getAuthHeader(config) {
    return config.user
        ? {
              Authorization:
                  'Basic ' + Buffer.from(`${config.user}:${config.password}`).toString('base64')
          }
        : {};
}

function timeout(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function getTaskFileUrl(time, taskId, inout, ext) {
    time = time.getTime();
    return `${time}-${taskId}.${inout}.${ext}`;
}

module.exports.runRemoteTask = runRemoteTask;
module.exports.startServer = startServer;
