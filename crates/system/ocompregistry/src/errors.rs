use outbe_primitives::error::PrecompileError;

pub(crate) fn corruption(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Fatal(message.into())
}
