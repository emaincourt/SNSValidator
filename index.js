import 'babel-polyfill';
import crypto from 'crypto';
import url from 'url';
import { mapKeys } from 'lodash';
import request from 'request-promise';

const mandatoryNKeys = [
  'Message',
  'MessageId',
  'Subject',
  'Timestamp',
  'TopicArn',
  'Type',
];

const mandatorySUKeys = [
  'Message',
  'MessageId',
  'SubscribeURL',
  'Timestamp',
  'Token',
  'TopicArn',
  'Type',
];

const legacyKeys = {
  SigningCertUrl: 'SigningCertURL',
  SubscribeUrl: 'SubscribeURL',
  UnsubscribeUrl: 'UnsubscribeURL',
};

class SNSValidator {
  constructor() {
    this.matchingPattern = /^sns\.[a-zA-Z0-9-]{3,}\.amazonaws\.com(\.cn)?$/;
  }

  isValidCertificateURL(certificateURL) {
    const uri = url.parse(certificateURL);
    return uri.protocol === 'https:'
        && uri.host.match(this.matchingPattern).length !== 0
        && uri.path.indexOf('.pem') === uri.path.length - 4;
  }

  normalizeLambdaMessage(object) {
    return mapKeys(object, (value, key) => (legacyKeys[key] ? legacyKeys[key] : key));
  }

  async getCertificate(uri) {
    return request(uri).catch((err) => { throw new Error(err); });
  }


  getStringToSign(message) {
    const keys = message.Type === 'Notification' ? mandatoryNKeys.slice(0) : mandatorySUKeys.slice(0);
    const str = keys.map((key) => {
      if (!Object.prototype.hasOwnProperty.call(message, key)) {
        throw new ReferenceError('Mandatory key missing.');
      }
      return `${key}\n${message[key]}\n`;
    });
    return str.join('');
  }

  checkSignature(stringToSign, certificate, signature) {
    const verifier = crypto.createVerify('RSA-SHA1');
    verifier.update(stringToSign);
    return verifier.verify(certificate, signature, 'base64');
  }

  async validate(message) {
    try {
      const normalizedMessage = this.normalizeLambdaMessage(message);

      if (!this.isValidCertificateURL(normalizedMessage.SigningCertURL)) {
        throw new ReferenceError();
      }
      const certificate = await this.getCertificate(normalizedMessage.SigningCertURL);
      const stringToSign = this.getStringToSign(normalizedMessage);
      return this.checkSignature(stringToSign, certificate, normalizedMessage.Signature);
    } catch (e) {
      return e;
    }
  }
}

export default SNSValidator;

