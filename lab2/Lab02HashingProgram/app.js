import * as crypto from "crypto";
import promptSync from "prompt-sync";
import fs from "fs";
import { readFile, writeFile } from "fs/promises"
import path from "path";
import { fileURLToPath } from "url";



const cwd = path.dirname(fileURLToPath(import.meta.url))
const prompt = promptSync()

function createSHA256Hash(message) {
	return crypto.createHash("sha256").update(message).digest("hex");
}


const getFiles = (directory) => {
	const directoryPath = path.join(cwd, directory);
	const files = []

	try {

		const readFiles = fs.readdirSync(directoryPath)
		readFiles.forEach((file) => {
			file = path.resolve(directory, file)
			files.push(file)
		})

	}
	catch (err) {
		console.log("unable to read directory" + err)
	}

	return files
}

const hashFile = async (file) => {
	console.log(file)
	const filePath = path.join(cwd, file)
	const fileBuffer = await readFile(filePath).catch((err) => {
		console.log(err)
	})
	return createSHA256Hash(fileBuffer)
}

const traverseDirectory = async (directory) => {
	const files = getFiles(directory)
	const hashes = []

	for (const file of files) {
		const hash = await hashFile(file)
		const newEntry = {
			filepath: file,
			hash: hash
		}
		hashes.push(newEntry)
		
	}

	return hashes
}




const generateTable = async (directory) => {
	// look through directory and generate hashes
	const hashTable = await traverseDirectory(directory)
	// store table in json file
	const jsonText = JSON.stringify(hashTable)
	await writeFile("hashes.json", jsonText, "utf-8")
		.then(() => console.log("Hash table Generated"))
		.catch((err) => { console.log(err) })
	

	return hashTable
}


const directory = prompt("enter a directory: ")
const hashes = await generateTable(directory);



