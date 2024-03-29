import AWS from "aws-sdk";
import fs from "fs";
import env from "dotenv";

env.config();
//credential for aws
const resgion: string = "us-east-1";
const Access_key: string = process.env.Access_key.toString();
const Secret_access_key: string = process.env.Secret_access_key.toString();
//map to choice which target
const Target = {
  1: "Date",
  2: "Timestamp",
  3: "IP addresse",
  4: "Error Codes",
};
// logfileNumber use it to indicate which file in Result.txt
var fileNumber: number = 0;
//connect to aws wiht credentials
AWS.config.update({
  region: resgion,
  credentials: new AWS.Credentials(Access_key, Secret_access_key),
});
//create txt file named Result
fs.writeFile("Result.txt", "", (err) => {
  if (err) {
    console.log(err);
  }
});
//make an instance of aws s3
const s3 = new AWS.S3();

//This Method used To Get All Files
s3.listObjectsV2({ Bucket: "threat-monitor-task" }, (err, data) => {
  if (err) {
    console.log(err);
  } else {
    // loop throw all files
    data.Contents.forEach((o) => {
      console.log(
        //This Method used To get a file and its content
        s3.getObject(
          { Bucket: "threat-monitor-task", Key: o.Key },
          (err, data) => {
            if (err) {
              console.log(err);
            } else {
              fs.appendFile(
                "Result.txt",
                `\nLogFileNumber:${++fileNumber} \n\n`,
                (err) => {
                  if (err) {
                    console.log(err);
                  }
                }
              );
              //Change The Target ===> 1: "Date",  2: "Timestamp",  3: "IP addresse", 4: "Error Codes",
              extractsSpecificInformation(data.Body.toString(), Target[2]);
            }
          }
        )
      );
    });
  }
});
//this method used for find a specific information for the log file, it takes logFile and Target to find it
const extractsSpecificInformation = (logFile: string, Target: string) => {
  //regular expression to split lines
  var Lines = logFile.split(/\r\n/);
  if (Target == "Date") {
    for (let i = 0; i < Lines.length - 1; i++) {
      //solit the line into three section first one contain timestamp, ip addres and date the second section contain label of the error message and the third section contain the message of the label
      var LineSeprated = Lines[i].split(" - ");
      //split the first section to get Date
      var firstSection = LineSeprated[0].split(" ");
      var Date = firstSection[0];
      //append the Date to the file
      fs.appendFile("Result.txt", `${Date} \n`, (err) => {
        if (err) {
          console.log(err);
        }
      });
    }
  }

  if (Target == "Timestamp") {
    for (let i = 0; i < Lines.length - 1; i++) {
      var LineSeprated = Lines[i].split(" - ");
      //split the first section to get Timestamp
      var firstSection = LineSeprated[0].split(" ");
      var Timestamp = firstSection[1];
      //append the Timestamp to the file
      fs.appendFile("Result.txt", `${Timestamp} \n`, (err) => {
        if (err) {
          console.log(err);
        }
      });
    }
  }

  if (Target == "IP addresse") {
    for (let i = 0; i < Lines.length - 1; i++) {
      var LineSeprated = Lines[i].split(" - ");
      //split the first section to get ipAddress
      var firstSection = LineSeprated[0].split(" ");
      var ipAddress = firstSection[2];
      //append the ipAddress to the file
      fs.appendFile("Result.txt", `${ipAddress} \n`, (err) => {
        if (err) {
          console.log(err);
        }
      });
    }
  }

  if (Target == "Error Codes") {
    for (let i = 0; i < Lines.length - 1; i++) {
      //split the line and use the label and its message(second Section and Third Section)
      var LineSeprated = Lines[i].split(" - ");
      //append the label and its message to the file
      fs.appendFile(
        "Result.txt",
        ` ${LineSeprated[1]}:  ${LineSeprated[2]} \n`,
        (err) => {
          if (err) {
            console.log(err);
          }
        }
      );
    }
  }
};
