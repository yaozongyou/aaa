pub use chrono::Local;
pub use gettid::gettid;

pub fn get_type_name<T: ?Sized>(_: &T) -> &'static str {
    return std::any::type_name::<T>();
}

#[macro_export]
macro_rules! aaa {
    ($($arg:tt)*) => {{
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut s = String::from(format!("[{} {} {}:{}] ", $crate::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"), $crate::gettid(),  file!(), line!()));
        s += &String::from(format!($($arg)*));

        if let Ok(mut f) = OpenOptions::new().write(true).append(true).create(true).open("/tmp/debug.txt") {
            writeln!(f, "{}", s).unwrap();
        }
    }}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    #[test]
    fn it_works() {
        aaa!("{} {}", "aaaa", 123);
        aaa!(
            "&7u32 as &dyn Debug type name: {}",
            get_type_name(&7u32 as &dyn Debug)
        );
        assert_eq!(2 + 2, 4);
    }
}
