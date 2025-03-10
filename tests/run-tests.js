import { runDidKeyTests } from './did-key.test.js';

console.log('📋 Running did-key tests...');

// Run all test suites
const didKeyResult = runDidKeyTests();

// Determine overall exit code
const exitCode = didKeyResult;

// Print final results
console.log('\n===== Test Run Complete =====');
if (exitCode === 0) {
  console.log('✅ All tests passed!');
} else {
  console.error('❌ Some tests failed!');
}

// Exit with appropriate code
process.exit(exitCode);
