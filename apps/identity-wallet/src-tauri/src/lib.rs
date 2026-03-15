#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greet_formats_name() {
        assert_eq!(greet("World".to_string()), "Hello, World!");
    }

    #[test]
    fn greet_empty_name() {
        assert_eq!(greet(String::new()), "Hello, !");
    }

    #[test]
    fn greet_special_characters() {
        assert_eq!(
            greet("<script>alert(1)</script>".to_string()),
            "Hello, <script>alert(1)</script>!"
        );
    }
}
