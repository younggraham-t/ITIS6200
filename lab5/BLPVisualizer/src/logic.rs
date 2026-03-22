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

    pub fn set_level(&mut self, new_level: SecurityLevel) {
        // don't allow level to decrease or go above maximum level
        if new_level <= self.max_sec_level && new_level >= self.cur_operating_level {
            self.cur_operating_level = new_level;
        }
    }

    fn as_str(&self) -> String {
        format!("[Subject] {}: CurLvl={}, MaxLvl={}", self.name, self.cur_operating_level.as_str(), self.max_sec_level.as_str())
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
        format!("[Object] {}: Lvl={}", self.name, self.sec_level.as_str())
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
    fn new(subject: Subject, object: Object, req_type: RequestType) -> Request {

        Request {
            subject, 
            object,
            request_type: req_type,
            allowed: false,
            info: "".to_string(),
        }
    }

    pub fn as_str(&self) -> String {
        let allow_string;
        if self.allowed {
            allow_string = format!("TRUE\tObj Lvl ({}) <= Subj Max ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
        }
        else {

            allow_string = format!("FALSE\tObj Lvl ({}) > Subj Max ({})", self.object.sec_level.as_str(), self.subject.max_sec_level.as_str());
        }
        format!("Action: {} {} {} \nAllow: {} \nINFO: {}", self.subject.name, self.request_type.as_str(), self.object.name, allow_string, self.info)

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

    fn get_subject_by_name(&self, name: &str) -> Result<&Subject, String> {
        for subject in &self.subjects {
            if subject.name == name {
                return Ok (subject)
            }
        }
        Err("no matching subject with that name".to_string())

    }
    
    
    fn get_object_by_name(&self, name: &str) -> Result<&Object, String> {
        for object in &self.objects {
            if object.name == name {
                
                return Ok (object)
            }
        }
        Err("no matching object with that name".to_string())

    }

    pub fn read(&self, subject_name: &str, object_name: &str) -> Result<Request, String> {
        //get the object and subject
        let subject_res = self.get_subject_by_name(subject_name);
        let object_res = self.get_object_by_name(object_name);
        let subject: Option<Subject>;
        let object: Option<Object>;

        match subject_res {
            Ok(s) => subject = Some(s.clone()),
            Err(e) => {
                subject = None;
                println!("failed to make check: {}", e)

            },
        }
        match object_res {
            Ok(o) => object = Some(o.clone()),
            Err(e) => {
                object = None;
                println!("failed to make check: {}", e)

            },
        }
        if let Some(object) = object && let Some(subject) = subject {
            let mut req = Request::new(subject, object, RequestType::Read);
            // make chack if the subject can read the object
            if req.subject.cur_operating_level >= req.object.sec_level {
               req.allowed = true;
            }
            else if req.subject.max_sec_level >= req.object.sec_level {
                req.subject.set_level(req.object.sec_level.clone());
                req.allowed = true;
                req.info = format!("Raising {}'s level to {}", req.subject.name, req.object.sec_level.as_str()).to_string()
            }
            else {
                req.allowed = false;
            }

            return Ok(req);
        }
        
        Err("Failed to find object/subject".to_string())
        
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
