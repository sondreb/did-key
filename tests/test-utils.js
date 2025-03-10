export class TestRunner {
  constructor() {
    this.totalTests = 0;
    this.passedTests = 0;
    this.failedTests = [];
  }

  test(name, testFn) {
    this.totalTests++;
    try {
      testFn();
      console.log(`✅ PASS: ${name}`);
      this.passedTests++;
    } catch (error) {
      console.error(`❌ FAIL: ${name}`);
      console.error(`   Error: ${error.message}`);
      this.failedTests.push({ name, error });
    }
  }

  assertEquals(actual, expected, message = '') {
    if (actual !== expected) {
      throw new Error(`${message} Expected ${expected}, but got ${actual}`);
    }
  }

  assertNotEquals(actual, expected, message = '') {
    if (actual === expected) {
      throw new Error(`${message} Expected ${actual} to be different from ${expected}`);
    }
  }
  
  assertTrue(value, message = '') {
    if (!value) {
      throw new Error(`${message} Expected value to be true`);
    }
  }
  
  assertFalse(value, message = '') {
    if (value) {
      throw new Error(`${message} Expected value to be false`);
    }
  }

  summarize() {
    console.log('\n----- Test Summary -----');
    console.log(`Total tests: ${this.totalTests}`);
    console.log(`Passed: ${this.passedTests}`);
    console.log(`Failed: ${this.failedTests.length}`);
    
    if (this.failedTests.length > 0) {
      console.log('\nFailed Tests:');
      this.failedTests.forEach((failure, index) => {
        console.log(`${index + 1}. ${failure.name}`);
      });
      return 1;
    }
    return 0;
  }
}
