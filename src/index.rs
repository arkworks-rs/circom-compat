use ark_ff::Field;
use ark_relations::utils::matrix::Matrix;

/// The A, B and C matrices of a Rank-One `ConstraintSystem`.
/// Also contains metadata on the structure of the constraint system
/// and the matrices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NPIndex<F: Field> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,

    /// The A constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub a: Matrix<F>,
    /// The B constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub b: Matrix<F>,
    /// The C constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub c: Matrix<F>,
}
