macro_rules! cfg_unix {
    ($($item:item)*) => {
        $(
            #[cfg(unix)]
            #[cfg_attr(docsrs, doc(cfg(unix)))]
            $item
        )*
    }
}
macro_rules! cfg_not_unix {
    ($($item:item)*) => {
        $(
            #[cfg(not(unix))]
            #[cfg_attr(docsrs, doc(cfg(not(unix))))]
            $item
        )*
    }
}
