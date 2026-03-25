#[derive(PartialEq, PartialOrd, Clone)]
pub enum SecurityLevel {
    U=0,
    C,
    S,
    TS,
}

impl SecurityLevel {
    fn as_str(&self) -> &'static str {
        match self {
            Self::U => "U",
            Self::C => "C",
            Self::S => "S",
            Self::TS => "TS",
        }
    }
}


#[derive(Clone)]
struct Subject {
    name: String,
    max_sec_level: SecurityLevel,
    cur_operating_level: SecurityLevel,
}

impl Subject {
    fn new(name: String, start_sec_level: SecurityLevel, max_sec_level: SecurityLevel) -> Result<Self, String> {
        if start_sec_level > max_sec_level {
            return Err("Starting security level cannot be higher than max security level".to_string());
        }

        Ok(Subject {
                name: name,
                max_sec_level: max_sec_level,
                cur_operating_level: start_sec_level,
            }
        )
    }

    fn set_level(&mut self, new_level: SecurityLevel) -> Result<(), String> {
        // don't allow level to decrease or go above maximum level
        if new_level <= self.max_sec_level {
            if new_level >= self.cur_operating_level {
                self.cur_operating_level = new_level;
                return Ok(());
            }
            else {
                return Err(format!("{} cannot set level to {}: level ({}) < SubjCurr ({})", self.as_str(), new_level.as_str(), new_level.as_str(), self.cur_operating_level.as_str()));
                
            }
        }
        Err(format!("{} cannot set level to {}: level ({}) > SubjMax ({})", self.as_str(), new_level.as_str(), new_level.as_str(), self.max_sec_level.as_str()))
    }

    fn as_str(&self) -> String {
        format!("(Subject) {}: CurLvl={}, MaxLvl={}", self.name, self.cur_operating_level.as_str(), self.max_sec_level.as_str())
    }
}

#[derive(Clone)]
struct Object {
    name: String,
    sec_level: SecurityLevel,
}

impl Object {
    fn new(name: String, sec_level: SecurityLevel) -> Object {
       Object {
           name: name,
           sec_level: sec_level,
       } 
    }
    fn as_str(&self) -> String {
        format!("(Object) {}: Lvl={}", self.name, self.sec_level.as_str())
    }
}

pub enum RequestType {
    Read,
    Write,
}
impl RequestType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

pub struct Request {
    subject: Subject,
    object: Object,
    request_type: RequestType,
    allowed: bool,
    info: String,
}

impl Request {

    pub fn as_str(&self) -> String {
        
        let allow_string;
        //format "allow" section Read requests need to have different signs for allow/disallow
        //compared to Write requests
        match self.request_type {
           RequestType::Read => {

                if self.allowed {
                    allow_string = format!("TRUE\tObj Lvl ({}) <= Subj Max ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
                }
                else {

                    allow_string = format!("FALSE\tObj Lvl ({}) > Subj Max ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
                }
           },
           RequestType::Write => {
               
                if self.allowed {
                    allow_string = format!("TRUE\tObj Lvl ({}) >= Subj Curr ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
                }
                else {

                    allow_string = format!("FALSE\tObj Lvl ({}) < Subj Curr ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
                }
           }
           
        }
        format!("> Action: {} {} {} \n> Allow: {} \n> INFO: {}", self.subject.name, self.request_type.as_str(), self.object.name, allow_string, self.info)

    }
}

pub struct BLPModel {
    subjects: Vec<Subject>,
    objects: Vec<Object>, 
    
}

impl BLPModel {
    pub fn new() -> BLPModel {
        let subjects: Vec<Subject> = vec![];
        let objects: Vec<Object> = vec![];
        BLPModel {
            subjects,
            objects,
        }

    }
    
    pub fn add_subject(&mut self, name: String, start_sec_level: SecurityLevel, max_sec_level: SecurityLevel) {
        
        let new_subject = Subject::new(name, start_sec_level, max_sec_level);
        // when subject is created it will return an Err if the start_sec_level is higher than the max_sec_level
        match new_subject {
            Ok(s) => self.subjects.push(s),
            Err(e) => println!("Failed to add subject: {}", e),
        }
        
    }

    pub fn add_object(&mut self, name: String, sec_level: SecurityLevel) {

        let new_object = Object::new(name, sec_level);
        self.objects.push(new_object)
    }

    // fn validate_levels(subject: Subject, object: Object) -> bool {
    //     return subject.cur_operating_level == object.sec_level;
    // }


    pub fn read(&mut self, subject_name: &str, object_name: &str) -> Result<Request, String> {
        //get the object and subject
        let subject = self.subjects.iter_mut().find(|s| s.name == subject_name).ok_or("Cannot find subject")?;
        let object = self.objects.iter().find(|o| o.name == object_name).ok_or("Cannot find object")?;
        
            
        let allowed;
        let mut info: String = "".to_string();
        //subject is allowed to read if their cur_level is above that of the object's
        if subject.cur_operating_level >= object.sec_level {
           allowed = true;
        }
        //subject also allowed if their max_level is above that of the object's
        else if subject.max_sec_level >= object.sec_level {
            allowed = true;
            let subject_level_check = subject.set_level(object.sec_level.clone());
            match subject_level_check {
                Ok(()) => info = format!("Raising {}'s level to {}", subject.name, object.sec_level.as_str()).to_string()
,
                Err(e) => println!("{}", e)

            }
                    }
        else {
            allowed = false;
        }

        Ok(Request {
            subject: subject.clone(),
            object: object.clone(),
            request_type: RequestType::Read,
            allowed,
            info,
            
        })
        
        
    }

    pub fn write(&mut self, subject_name: &str, object_name: &str) -> Result<Request, String> {

        let subject = self.subjects.iter_mut().find(|s| s.name == subject_name).ok_or("Cannot find subject")?;
        let object = self.objects.iter().find(|o| o.name == object_name).ok_or("Cannot find object")?;
        
        let allowed;
        let info: String = "".to_string();
        //subject is allowed to write if their level is lower than or equal to the object's
        if subject.cur_operating_level <= object.sec_level {
           allowed = true;
        }
        else {
            allowed = false;
        }
        
        Ok(Request {
            subject: subject.clone(),
            object: object.clone(),
            request_type: RequestType::Write,
            allowed,
            info,
            
        })
    }
    
    pub fn set_level(&mut self, subject_name: &str, new_level: SecurityLevel) {

        //get the subject
        let subject_search = self.subjects.iter_mut().find(|s| s.name == subject_name);


        if let Some(subject) = subject_search {
            //set subject level 
            match subject.set_level(new_level.clone()) {
                Ok(()) => println!("{} successfully changed level to {}", subject.as_str(), new_level.as_str()),
                Err(e) => println!("{}", e)

            }

        }
        else {
            println!("Cannot find subject from name: {}", subject_name)
        }

    } 

    
    pub fn print_current_state(&self) {
        println!("--- Current BLP State ---");
        for subject in &self.subjects {
            println!("{}", subject.as_str());
        }
        for object in &self.objects {
            println!("{}", object.as_str());
        }
        println!("-------------------------");
        
    }


}
