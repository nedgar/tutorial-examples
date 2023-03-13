const Operators = {
  NOOP: 0, // No operation, skip query verification in circuit
  EQ: 1, // equal
  LT: 2, // less than
  GT: 3, // greater than
  IN: 4, // in
  NIN: 5, // not in
  NE: 6, // not equal
};

function isMultiValuedOp(op) {
  return [Operators.IN, Operators.NIN].includes(op);
}

async function main() {
  // address of the ERC20Verifier contract
  const { ERC20_VERIFIER_ADDRESS } = process.env;

  const erc20Verifier = await hre.ethers.getContractAt(
    "ERC20Verifier",
    ERC20_VERIFIER_ADDRESS
  );

  const validatorNames = {
    "0x3DcAe4c8d94359D31e4C89D7F2b944859408C618":
      "CredentialAtomicQueryMTPValidator",
    "0xF2D4Eeb4d455fb673104902282Ce68B9ce4Ac450":
      "CredentialAtomicQuerySigValidator",
  };

  try {
    const supportedRequests = await erc20Verifier.getSupportedRequests();
    const requestIDs = supportedRequests.map((id) => id.toBigInt()).sort();
    console.log("Supported request IDS:", requestIDs);
    for (let requestID of requestIDs) {
      const request = await erc20Verifier.getZKPRequest(requestID);
      const op = request.operator.toNumber();
      const opName = Object.keys(Operators).find((k) => Operators[k] === op);
      const values =
        op === Operators.NOOP
          ? []
          : isMultiValuedOp(op)
          ? request.values
          : [request.value[0]];

      const validatorAddress = await erc20Verifier.requestValidators(requestID);

      console.log(`Request ${requestID}:`, {
        schema: request.schema.toBigInt(),
        claimPathKey: request.claimPathKey.toBigInt(),
        operator: op,
        _operatorName: typeof opName === "string" ? "$" + opName : "<unknown>",
        value: values.map((v) => v.toBigInt()),
        queryHash: request.queryHash.toBigInt(),
        circuitId: request.circuitId,
        validatorAddress,
        _validatorName: validatorNames[validatorAddress] ?? "<unknown>",
      });
    }
  } catch (e) {
    console.log("error: ", e);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
