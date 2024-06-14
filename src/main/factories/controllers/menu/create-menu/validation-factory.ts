import { RequiredFieldValidation } from "@infra/http/validation/RequiredFieldValidation";
import { ValidationComposite } from "@infra/http/validation/ValidationComposite";






export const createMenuValidation = (): ValidationComposite => {
  return new ValidationComposite(
    [

      new RequiredFieldValidation("place_id"),
      // new RequiredFieldValidation("foods"),
    ],
    "body"
  );
};
