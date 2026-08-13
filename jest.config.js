module.exports = {
  testEnvironment: 'node',
  transform: {},
  moduleNameMapper: {
    '^@ostro/support/(.*)$': '<rootDir>/../support/$1',
    '^@ostro/support$': '<rootDir>/../support',
    '^@ostro/contracts/(.*)$': '<rootDir>/../contracts/$1',
    '^@ostro/contracts$': '<rootDir>/../contracts',
    '^@ostro/console/(.*)$': '<rootDir>/../console/$1',
    '^@ostro/console$': '<rootDir>/../console'
  }
};
