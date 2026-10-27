pub mod a {
    pub mod b {
        pub mod c {
            pub(in super::super) mod up_two {}
            pub(in crate::a) mod in_a {}
            pub(super) mod parent {}
            pub(self) mod own {}
        }
    }
}
