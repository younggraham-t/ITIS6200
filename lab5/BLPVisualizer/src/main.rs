use crate::logic::Request;
use crate::logic::SecurityLevel;
use crate::logic::BLPModel;

mod logic;

fn init_blp_model() -> BLPModel {
    println!("[System] Initializing Default State");
    
    let mut blp_model = BLPModel::new();
    //add subjects
    blp_model.add_subject("Alice".to_string(), SecurityLevel::U, SecurityLevel::S);
    blp_model.add_subject("Bob".to_string(), SecurityLevel::C, SecurityLevel::C);
    blp_model.add_subject("Eve".to_string(), SecurityLevel::U, SecurityLevel::U);

    //add objects
    blp_model.add_object("pub.txt".to_string(), SecurityLevel::U);
    blp_model.add_object("emails.txt".to_string(), SecurityLevel::C);
    blp_model.add_object("username.txt".to_string(), SecurityLevel::S);
    blp_model.add_object("password.txt".to_string(), SecurityLevel::TS);
    
    blp_model
}

fn print_results(res: &Result<Request, String>, blp_model: &BLPModel) {
    match res {
        Ok(req) => {
            println!("{}", req.as_str())

        }
        Err(e) => println!("case failed to run: {}", e)
    }
    
    blp_model.print_current_state();
}


fn main() {
    
     


    //Case 1
    println!("============Case 1============");
    let mut blp_model = init_blp_model();
    let mut res = blp_model.read("Alice", "emails.txt");
    print_results(&res, &blp_model);
    

    //Case 2
    println!("============Case 2============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "password.txt");
    print_results(&res, &blp_model);
    
    
    //Case 3
    println!("============Case 3============");
    blp_model = init_blp_model();
    res = blp_model.read("Eve", "pub.txt");
    print_results(&res, &blp_model);
    
    
    //Case 4
    println!("============Case 4============");
    blp_model = init_blp_model();
    res = blp_model.read("Eve", "emails.txt");
    print_results(&res, &blp_model);


    //Case 5
    println!("============Case 5============");
    blp_model = init_blp_model();
    res = blp_model.read("Bob", "password.txt");
    print_results(&res, &blp_model);
    
    
    //Case 6
    println!("============Case 6============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "pub.txt");
    print_results(&res, &blp_model);
    
    //Case 7
    println!("============Case 7============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "password.txt");
    print_results(&res, &blp_model);
    
    
    //Case 8
    println!("============Case 8============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Alice", "username.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "emails.txt");
    print_results(&res, &blp_model);
    
    
    //Case 9
    println!("============Case 9============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "username.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Alice", "password.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "password.txt");
    print_results(&res, &blp_model);
    
    //Case 10
    println!("============Case 10============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Bob", "emails.txt");
    print_results(&res, &blp_model);
    
    //Case 11
    println!("============Case 11============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "username.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Bob", "username.txt");
    print_results(&res, &blp_model);
    
    
    //Case 12
    println!("============Case 12============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "password.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Bob", "password.txt");
    print_results(&res, &blp_model);
    
    
    //Case 13
    println!("============Case 13============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Eve", "emails.txt");
    print_results(&res, &blp_model);
    
    
    //Case 14
    println!("============Case 14============");
    blp_model = init_blp_model();
    res = blp_model.read("Alice", "emails.txt");
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Eve", "pub.txt");
    print_results(&res, &blp_model);


    //Case 15
    println!("============Case 15============");
    blp_model = init_blp_model();
    let level = blp_model.set_level("Alice", SecurityLevel::S);
    print_results(&res, &blp_model);
    res = blp_model.write("Alice", "pub.txt");
    print_results(&res, &blp_model);
    res = blp_model.read("Eve", "pub.txt");
    print_results(&res, &blp_model);


}
