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




const generateTable = async (directory, hashFile="hashes.json") => {
	//check if there is already a hashtable for the directory
	// look through directory and generate hashes
	const hashTable = await traverseDirectory(directory)
	// store table in json file
	const jsonText = JSON.stringify(hashTable)

	hashFile = path.join(cwd, hashFile)
	await writeFile(hashFile, jsonText, "utf-8")
		.then(() => console.log("Hash table Generated"))
		.catch((err) => { console.log(err) })
	

	return hashTable
}


const validateHashes = async (directory, hashFile="hashes.json") => {
	
	const hashTable = await traverseDirectory(directory)
	
	const hashFilePath = path.join(cwd, hashFile)
	const hashesFromFile = await readFile(hashFilePath).then((contents) => JSON.parse(contents))
	

	
	let updateTable = false
	
		// console.log(hashFile)
		
		
	
		
	const matches = hashTable.map((file) => {
		const innerMap = hashesFromFile.map((hashFile) => {
			const pathMatch = file.filepath === hashFile.filepath
			const hashMatch = file.hash === hashFile.hash

			return {
				originalPath: hashFile.filepath,
				newPath: file.filepath,
				originalHash: hashFile.hash,
				newHash: file.hash,
				pathMatch: pathMatch,
				hashMatch: hashMatch,

			}
		})
		



		return innerMap

	})
	// console.log(matches)

	const filteredMatches = matches.flatMap(match => {
		return match.filter(item => item.hashMatch || item.pathMatch)
	} )

	// if hashMatch but not pathMatch file was renamed
	const renamedFiles = filteredMatches.filter(item => item.hashMatch && !item.pathMatch)
	
	// if pathMatch but not hashMatch file was modified/invalid
	const invalidFiles = filteredMatches.filter(item => !item.hashMatch)

	// if path and hash match file is valid
	const validFiles = filteredMatches.filter(item => item.hashMatch)

	// get all unique values for originalPath and newPath
	const allOriginalPaths = [...new Set(matches[0].map(item => item.originalPath))]
	const allNewPaths = [...new Set(matches.map(item => item[0].newPath))]
	
	// if value exists in originalPath but not newPath file was deleted
	let deletedFiles = allOriginalPaths.filter(path => !allNewPaths.includes(path))
	//remove any entries that are in the renamed files
	deletedFiles = deletedFiles.filter(path => !renamedFiles.map(file => file.originalPath).includes(path))
	
	// if value exists in newPath but not originalPath file was added
	let addedFiles = allNewPaths.filter(path => !allOriginalPaths.includes(path))
	// remove any entries taht are in the renamed files
	addedFiles = addedFiles.filter(path => !renamedFiles.map(file => file.newPath).includes(path))

	//print out results
	deletedFiles.forEach(file => console.log(`File ${file} was deleted`))
	addedFiles.forEach(file => console.log(`File ${file} added`))
	renamedFiles.forEach(file => console.log(`File name change detected, ${file.originalPath} renamed to ${file.newPath}`))
	validFiles.forEach(file => console.log(
		`File ${renamedFiles.map(file => file.originalPath).includes(path) ? file.originalPath : file.newPath} is valid`))
	invalidFiles.forEach(file => console.log(`File ${file.originalPath} is invalid`))
	
		
		

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

const customHashFile = prompt("Do you wish to enter a custom hash table file path? (Default './hashes.json')", {value: "hashes.json"})
await userChoices[userChoice](directory, customHashFile)


