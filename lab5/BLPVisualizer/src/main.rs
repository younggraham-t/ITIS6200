use crate::logic::Request;
use crate::logic::SecurityLevel;
use crate::logic::BLPModel;

mod logic;

fn init_blp_model(blp_model: &mut BLPModel) {
    println!("Initializing Default State");
    //add subjects
    blp_model.add_subject("Alice".to_string(), SecurityLevel::U, SecurityLevel::S);
    blp_model.add_subject("Bob".to_string(), SecurityLevel::C, SecurityLevel::C);
    blp_model.add_subject("Eve".to_string(), SecurityLevel::U, SecurityLevel::U);

    //add objects
    blp_model.add_object("pub.txt".to_string(), SecurityLevel::U);
    blp_model.add_object("emails.txt".to_string(), SecurityLevel::C);
    blp_model.add_object("username.txt".to_string(), SecurityLevel::S);
    blp_model.add_object("password.txt".to_string(), SecurityLevel::TS);
    
}

fn print_results(res: Result<Request, String>, blp_model: &BLPModel) {
    match res {
        Ok(req) => {
            println!("{}", req.as_str())

        }
        Err(e) => println!("case failed to run: {}", e)
    }
    
    blp_model.print_current_state();
}


fn main() {
    let mut blp_model = BLPModel::new();
    
    init_blp_model(&mut blp_model);
     


    //Case 1
    println!("============Case 1============");
    init_blp_model(&mut blp_model);
    let mut res = blp_model.read("Alice", "emails.txt");
    print_results(res, &blp_model);
    

    //Case 2
    println!("============Case 2============");
    init_blp_model(&mut blp_model);
    res = blp_model.read("Alice", "password.txt");
    print_results(res, &blp_model);
    
    


}
