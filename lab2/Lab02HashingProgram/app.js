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
	// console.log(file)
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
	//check if there is already a hashtable for the directory
	// look through directory and generate hashes
	const hashTable = await traverseDirectory(directory)
	// store table in json file
	const jsonText = JSON.stringify(hashTable)
	let hashFile = prompt("Do you wish to enter a custom hash table file path? (Default './hashes.json')", {value: "hashes.json"})

	hashFile = path.join(cwd, hashFile)
	await writeFile(hashFile, jsonText, "utf-8")
		.then(() => console.log("Hash table Generated"))
		.catch((err) => { console.log(err) })
	

	return hashTable
}


const validateHashes = async (directory) => {
	
	const hashFile = prompt("Do you wish to enter a custom hash table file path? (Default './hashes.json')", {value: "hashes.json"})
	
	const hashTable = await traverseDirectory(directory)
	
	const hashFilePath = path.join(cwd, hashFile)
	const hashesFromFile = await readFile(hashFilePath).then((contents) => JSON.parse(contents))
	

	
	let updateTable = false
	
	for (const hashFile of hashTable) {
		// console.log(hashFile)
		
		const hashMatch = hashesFromFile.some(file => file.hash === hashFile.hash) 
		const filepathMatch = hashesFromFile.some(file => file.filepath === hashFile.filepath) 

		// console.log(filepathMatch + " filepath match")
		// console.log(hashMatch + " hash match")
		

		
		if (hashMatch) {
			console.log(hashFile.filepath + " is valid")
			if (!filepathMatch) {
				console.log("File name has changed updating hash table after all checks")
				updateTable = true
			}
		}
		else {
			console.log(hashFile.filepath + " is not valid")

		}
		

	}
	if (updateTable) {
		await generateTable(directory)
	}
	
}



const userChoices = {
	"G": generateTable,
	"V": validateHashes,
}

const userChoice = prompt("Choose whether to Generate or Validate: [G/V] Generate by default ", {value: "G"})
userChoice.toUpperCase()
const directory = prompt("Enter a directory: (default /testFiles)", {value: "/testFiles"})

await userChoices[userChoice](directory)


