extern crate bcrypt;
extern crate bellman;
extern crate bls12_381;
extern crate rand;
extern crate sha2;

use bcrypt::{hash, DEFAULT_COST};
use bellman::{
    Circuit, ConstraintSystem, SynthesisError, 
    groth16::{generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof as groth16_verify_proof}
};
use bls12_381::{Bls12, Scalar};
use rand::thread_rng;

struct User {
    username: String,
    password_hash: String,
}

fn register_user(username: String, password: String) -> User {
    let password_hash = hash_password(&password).unwrap();
    User {
        username,
        password_hash,
    }
}

fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

struct CredentialProofCircuit {
    pre_image: Option<Scalar>,
    hash: Option<Scalar>,
}

impl Circuit<Scalar> for CredentialProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let pre_image_var = cs.alloc(|| "pre_image", || {
            self.pre_image.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let hash_var = cs.alloc_input(|| "hash", || {
            self.hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce(
            || "double pre_image constraint",
            |lc| lc + pre_image_var,
            |lc| lc + pre_image_var,
            |lc| lc + hash_var,
        );

        Ok(())
    }
}

fn main() {
    let user = register_user("alice".to_string(), "password123".to_string());

    let example_pre_image = Scalar::from(123456789u64); // Dummy private input
    let example_hash = Scalar::from(123456789u64 * 2); // Dummy public input

    let params_circuit = CredentialProofCircuit {
        pre_image: Some(example_pre_image),
        hash: Some(example_hash),
    };

    let proof_circuit = CredentialProofCircuit {
        pre_image: Some(example_pre_image),
        hash: Some(example_hash),
    };


    let params = generate_random_parameters::<Bls12, _, _>(params_circuit, &mut thread_rng()).unwrap();

    let proof = create_random_proof(proof_circuit, &params, &mut thread_rng()).unwrap();

    println!("Proof generated for user: {}", user.username);

    // Verify proof
    let pvk = prepare_verifying_key(&params.vk);
    let inputs = vec![Scalar::from(123456789u64 * 2)];
    assert!(groth16_verify_proof(&pvk, &proof, &inputs).is_ok(), "Proof verification failed");

    println!("Proof verified for user: {}", user.username);
}
