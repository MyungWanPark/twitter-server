import httpMocks from "node-mocks-http";
import { isAuth } from "../auth.js";
import { faker } from "@faker-js/faker";
import jwt from "jsonwebtoken";
import * as userRepository from "../../data/userRepository.js";

jest.mock("jsonwebtoken");
jest.mock("../../data/userRepository.js");

describe("Auth Middleware", () => {
  it("returns 401 for the request without Authorization header", async () => {
    // given
    const request = httpMocks.createRequest({
      method: "GET",
      url: "/tweets",
    });
    const response = httpMocks.createResponse();
    const next = jest.fn();

    // when
    await isAuth(request, response, next);

    // then
    testValidation(response, next);
  });

  it("returns 401 for the request with unsupported Authorization header", async () => {
    // given
    const request = httpMocks.createRequest({
      method: "GET",
      url: "/tweets",
      headers: {
        authorization: "Basic",
      },
    });
    const response = httpMocks.createResponse();
    const next = jest.fn();

    // when
    await isAuth(request, response, next);

    // then
    testValidation(response, next);
  });

  it("returns 401 for the request with invalid jwt", async () => {
    // given
    const token = faker.string.alphanumeric(128);
    const request = httpMocks.createRequest({
      method: "GET",
      url: "/tweets",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
    const response = httpMocks.createResponse();
    const next = jest.fn();
    jwt.verify = jest.fn((token, secret, callback) => {
      callback(new Error("Bad token"), undefined);
    });

    // when
    await isAuth(request, response, next);

    // then
    testValidation(response, next);
  });

  it("returns 401 when cannot find a user by id from JWT", async () => {
    // given
    const token = faker.string.alphanumeric(128);
    const userId = faker.string.alphanumeric(32);
    const request = httpMocks.createRequest({
      method: "GET",
      url: "/tweets",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
    const response = httpMocks.createResponse();
    const next = jest.fn();
    jwt.verify = jest.fn((token, secret, callback) => {
      callback(null, { id: userId });
    });
    userRepository.findById = jest.fn(() => {
      return Promise.resolve(null);
    });
    // when
    await isAuth(request, response, next);

    // then
    testValidation(response, next);
  });
});

const testValidation = (response, next) => {
  expect(response.statusCode).toBe(401);
  expect(response._getJSONData().message).toBe("Authenication Error");
  expect(next).not.toBeCalled();
};
